use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    halo2_proofs::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::{
            bn256::{Fq, Fq2, Fr},
            FieldExt,
        },
        plonk::{Circuit, ConstraintSystem, Error},
    },
    utils::{biguint_to_fe, decompose_biguint},
    AssignedValue, Context, ContextParams, QuantumCell,
};
use halo2_ecc::{
    bigint::CRTInteger,
    bn254::{Fp2Chip, FpChip},
    ecc::{get_naf, EcPoint},
    fields::{
        fp::{FpConfig, FpStrategy},
        FieldChip, FieldExtPoint,
    },
};
use num_bigint::BigUint;
use num_traits::Num;

const K: usize = 16;

const NUM_ADVICE: usize = 20;
const NUM_LOOKUP_ADVICE: usize = 6;
const LIMB_BITS: usize = 90;
const NUM_LIMBS: usize = 3;
const LOOKUP_BITS: usize = 15;
const NUM_FIXED: usize = 1;

pub fn assert_eq<'v>(
    a: &FieldExtPoint<CRTInteger<'v, Fr>>,
    x_dec: &str,
    y_dec: &str,
    num_limbs: usize,
    limb_bits: usize,
) {
    let x = decompose_biguint::<Fr>(
        &BigUint::from_str_radix(x_dec, 10).unwrap(),
        num_limbs,
        limb_bits,
    );
    let y = decompose_biguint::<Fr>(
        &BigUint::from_str_radix(y_dec, 10).unwrap(),
        num_limbs,
        limb_bits,
    );

    let a_x = &a.coeffs[0];
    let a_y = &a.coeffs[1];

    for i in 0..num_limbs {
        a_x.limbs()[i].value().assert_if_known(|&&val| val == x[i]);
        a_y.limbs()[i].value().assert_if_known(|&&val| val == y[i]);
    }
}

pub fn fq2_from_hex<'v>(
    ctx: &mut Context<'v, Fr>,
    chip: &Fp2Chip<Fr>,
    x_dec: &str,
    y_dec: &str,
) -> FieldExtPoint<CRTInteger<'v, Fr>> {
    let c0 = biguint_to_fe::<Fq>(&BigUint::from_str_radix(x_dec, 10).unwrap());
    let c1 = biguint_to_fe::<Fq>(&BigUint::from_str_radix(y_dec, 10).unwrap());

    chip.load_constant(ctx, Fq2 { c0, c1 })
}

pub fn pow<'v>(
    ctx: &mut Context<'v, Fr>,
    chip: &Fp2Chip<Fr>,
    a: &FieldExtPoint<CRTInteger<'v, Fr>>,
    exp: Vec<u64>,
) -> FieldExtPoint<CRTInteger<'v, Fr>> {
    let mut res = a.clone();
    let mut is_started = false;
    let naf = get_naf(exp);

    for &z in naf.iter().rev() {
        if is_started {
            res = chip.mul(ctx, &res, &res);
        }
        if z != 0 {
            assert!(z == 1 || z == -1);
            if is_started {
                res = if z == 1 {
                    chip.mul(ctx, &res, a)
                } else {
                    chip.divide(ctx, &res, a)
                };
            } else {
                assert_eq!(z, 1);
                is_started = true;
            }
        }
    }
    res
}

pub fn pow_base<'v>(
    ctx: &mut Context<'v, Fr>,
    chip: &FpChip<Fr>,
    a: &CRTInteger<'v, Fr>,
    exp: Vec<u64>,
) -> CRTInteger<'v, Fr> {
    let mut res = a.clone();
    let mut is_started = false;
    let naf = get_naf(exp);

    for &z in naf.iter().rev() {
        if is_started {
            res = chip.mul(ctx, &res, &res);
        }
        if z != 0 {
            assert!(z == 1 || z == -1);
            if is_started {
                res = if z == 1 {
                    chip.mul(ctx, &res, a)
                } else {
                    chip.divide(ctx, &res, a)
                };
            } else {
                assert_eq!(z, 1);
                is_started = true;
            }
        }
    }
    res
}

pub fn sqrt<'v>(
    ctx: &mut Context<'v, Fr>,
    flex_chip: &FlexGateConfig<Fr>,
    chip: &FpChip<Fr>,
    chip2: &Fp2Chip<Fr>,
    a: &FieldExtPoint<CRTInteger<'v, Fr>>,
) -> FieldExtPoint<CRTInteger<'v, Fr>> {
    let p = BigUint::from_str_radix(&Fq::MODULUS[2..], 16).unwrap();
    let k = (p.clone() - BigUint::from(3u32)) / BigUint::from(4u32);
    let k_vec = k.to_u64_digits();
    let l = (p.clone() - BigUint::from(1u32)) / BigUint::from(2u32);
    let l_vec = l.to_u64_digits();

    let a1 = pow(ctx, chip2, a, k_vec);
    let a1_sq = chip2.mul(ctx, &a1, &a1);
    let alpha = chip2.mul(ctx, &a1_sq, &a);
    let x0 = chip2.mul(ctx, &a1, &a);

    let f01_const = chip2.load_constant(
        ctx,
        Fq2 {
            c0: Fq::zero(),
            c1: Fq::one(),
        },
    );
    let ret0 = chip2.mul(ctx, &x0, &f01_const);
    let alpha_plus_1 = chip2.add_constant_no_carry(ctx, &alpha, Fq2::one());
    let b = pow(ctx, chip2, &alpha_plus_1, l_vec);
    let ret1 = chip2.mul(ctx, &x0, &b);

    let mod_minus_one = p - BigUint::from(1u32);
    let mod_minus_one_const = chip.load_constant(ctx, mod_minus_one);

    let alpha_x = &alpha.coeffs[0];
    let alpha_y = &alpha.coeffs[1];
    let flag0 = chip.is_equal(ctx, alpha_x, &mod_minus_one_const);
    let flag1 = chip.is_zero(ctx, alpha_y);
    let flag0 = QuantumCell::Existing(&flag0);
    let flag1 = QuantumCell::Existing(&flag1);
    let and_flag = flex_chip.and(ctx, flag0, flag1);
    let ret = chip2.select(ctx, &ret0, &ret1, &and_flag);

    chip2.carry_mod(ctx, &ret)
}

pub fn g<'v>(
    ctx: &mut Context<'v, Fr>,
    chip2: &Fp2Chip<Fr>,
    z: &FieldExtPoint<CRTInteger<'v, Fr>>,
    b_coeff: &FieldExtPoint<CRTInteger<'v, Fr>>,
) -> FieldExtPoint<CRTInteger<'v, Fr>> {
    let z_3 = pow(ctx, chip2, z, vec![3]);
    let z_3_plus_b = chip2.add_no_carry(ctx, &z_3, &b_coeff);
    z_3_plus_b
}

pub fn sign0_fp<'v>(
    ctx: &mut Context<'v, Fr>,
    flex_chip: &FlexGateConfig<Fr>,
    limb_bits: usize,
    z: &CRTInteger<'v, Fr>,
) -> AssignedValue<'v, Fr> {
    let first_limb = &z.limbs()[0];
    let bits = flex_chip.num_to_bits(ctx, first_limb, limb_bits);
    bits[0].clone()
}

pub fn sign0_fp2<'v>(
    ctx: &mut Context<'v, Fr>,
    flex_chip: &FlexGateConfig<Fr>,
    limb_bits: usize,
    a: &FieldExtPoint<CRTInteger<'v, Fr>>,
) -> AssignedValue<'v, Fr> {
    let x = &a.coeffs[0];
    let sign_0 = sign0_fp(ctx, flex_chip, limb_bits, x);
    let y = &a.coeffs[1];
    let sign_1 = sign0_fp(ctx, flex_chip, limb_bits, y);
    let not_sign_0 = flex_chip.not(ctx, QuantumCell::Existing(&sign_0));
    flex_chip.mul_add(
        ctx,
        QuantumCell::Existing(&sign_1),
        QuantumCell::Existing(&not_sign_0),
        QuantumCell::Existing(&sign_0),
    )
}

pub fn is_square_fp<'v>(
    ctx: &mut Context<'v, Fr>,
    flex_chip: &FlexGateConfig<Fr>,
    chip: &FpChip<Fr>,
    a: &CRTInteger<'v, Fr>,
) -> AssignedValue<'v, Fr> {
    let p = BigUint::from_str_radix(&Fq::MODULUS[2..], 16).unwrap();
    let l = (p.clone() - BigUint::from(1u32)) / BigUint::from(2u32);
    let l_vec = l.to_u64_digits();
    let exp = pow_base(ctx, chip, a, l_vec);
    let mod_minus_one = p - BigUint::from(1u32);
    let mod_minus_one_const = chip.load_constant(ctx, mod_minus_one);

    let is_eq = chip.is_equal(ctx, &exp, &mod_minus_one_const);
    flex_chip.not(ctx, QuantumCell::Existing(&is_eq))
}

pub fn is_square_fp2<'v>(
    ctx: &mut Context<'v, Fr>,
    flex_chip: &FlexGateConfig<Fr>,
    chip: &FpChip<Fr>,
    a: &FieldExtPoint<CRTInteger<'v, Fr>>,
) -> AssignedValue<'v, Fr> {
    let x = &a.coeffs[0];
    let y = &a.coeffs[1];
    let x_sq = chip.mul(ctx, &x, &x);
    let y_sq = chip.mul(ctx, &y, &y);
    let z = chip.add_no_carry(ctx, &x_sq, &y_sq);

    is_square_fp(ctx, flex_chip, chip, &z)
}

pub fn map_to_curve<'v>(
    ctx: &mut Context<'v, Fr>,
    flex_chip: &FlexGateConfig<Fr>,
    fp_chip: &FpChip<Fr>,
    fp2_chip: &Fp2Chip<Fr>,
    u: &FieldExtPoint<CRTInteger<'v, Fr>>,
) -> EcPoint<Fr, FieldExtPoint<CRTInteger<'v, Fr>>> {
    let limb_bits = fp_chip.limb_bits;

    let b_coeff = fq2_from_hex(
        ctx,
        &fp2_chip,
        "19485874751759354771024239261021720505790618469301721065564631296452457478373",
        "266929791119991161246907387137283842545076965332900288569378510910307636690",
    );

    let z = fp2_chip.load_constant(ctx, Fq2::one());

    let c1 = fq2_from_hex(
        ctx,
        &fp2_chip,
        "19485874751759354771024239261021720505790618469301721065564631296452457478374",
        "266929791119991161246907387137283842545076965332900288569378510910307636690",
    );

    let c2 = fq2_from_hex(
        ctx,
        &fp2_chip,
        "10944121435919637611123202872628637544348155578648911831344518947322613104291",
        "0",
    );

    let c3 = fq2_from_hex(
        ctx,
        &fp2_chip,
        "18992192239972082890849143911285057164064277369389217330423471574879236301292",
        "21819008332247140148575583693947636719449476128975323941588917397607662637108",
    );

    let c4 = fq2_from_hex(
        ctx,
        &fp2_chip,
        "10499238450719652342378357227399831140106360636427411350395554762472100376473",
        "6940174569119770192419592065569379906172001098655407502803841283667998553941",
    );

    let u_sq = fp2_chip.mul(ctx, &u, &u);
    let tv1_imid = fp2_chip.mul(ctx, &u_sq, &c1);
    let one_const = fp2_chip.load_constant(ctx, Fq2::one());
    let tv1 = fp2_chip.sub_no_carry(ctx, &one_const, &tv1_imid);
    let tv2 = fp2_chip.add_no_carry(ctx, &one_const, &tv1_imid);
    let tv1_mul_tv2 = fp2_chip.mul(ctx, &tv1, &tv2);
    let tv3 = fp2_chip.divide(ctx, &one_const, &tv1_mul_tv2);
    let tv1_mul_tv3 = fp2_chip.mul(ctx, &tv1, &tv3);
    let tv1_mul_tv3_c3 = fp2_chip.mul(ctx, &tv1_mul_tv3, &c3);
    let tv4 = fp2_chip.mul(ctx, &u, &tv1_mul_tv3_c3);

    let x1 = fp2_chip.sub_no_carry(ctx, &c2, &tv4);
    let gx1 = g(ctx, &fp2_chip, &x1, &b_coeff);
    let is_gx1_sq = is_square_fp2(ctx, &flex_chip, &fp_chip, &gx1);
    let x2 = fp2_chip.add_no_carry(ctx, &c2, &tv4);
    let gx2 = g(ctx, &fp2_chip, &x2, &b_coeff);
    let is_gx2_sq = is_square_fp2(ctx, &flex_chip, &fp_chip, &gx2);
    let tv2_sq = fp2_chip.mul(ctx, &tv2, &tv2);
    let tv2_sq_mul_tv3 = fp2_chip.mul(ctx, &tv2_sq, &tv3);
    let sq_tv2_sq_mul_tv3 = fp2_chip.mul(ctx, &tv2_sq_mul_tv3, &tv2_sq_mul_tv3);
    let c4_mul_sq_tv2_sq_mul_tv3 = fp2_chip.mul(ctx, &c4, &sq_tv2_sq_mul_tv3);
    let x3 = fp2_chip.add_no_carry(ctx, &c4_mul_sq_tv2_sq_mul_tv3, &z);

    let x2_or_x3 = fp2_chip.select(ctx, &x2, &x3, &is_gx2_sq);
    let x = fp2_chip.select(ctx, &x1, &x2_or_x3, &is_gx1_sq);
    let gx = g(ctx, &fp2_chip, &x, &b_coeff);
    let y_imid = sqrt(ctx, &flex_chip, &fp_chip, &fp2_chip, &gx);
    let y_sign = sign0_fp2(ctx, &flex_chip, limb_bits, &y_imid);
    let u_sign = sign0_fp2(ctx, &flex_chip, limb_bits, &u);
    let is_sign_same = flex_chip.is_equal(
        ctx,
        QuantumCell::Existing(&u_sign),
        QuantumCell::Existing(&y_sign),
    );
    let y_imid_neg = fp2_chip.negate(ctx, &y_imid);
    let y_imid_neg = fp2_chip.carry_mod(ctx, &y_imid_neg);
    let y = fp2_chip.select(ctx, &y_imid, &y_imid_neg, &is_sign_same);

    let x = fp2_chip.carry_mod(ctx, &x);
    let y = fp2_chip.carry_mod(ctx, &y);
    EcPoint::construct(x, y)
}

#[derive(Clone, Default)]
struct MyCircuit;

impl Circuit<Fr> for MyCircuit {
    type Config = FpConfig<Fr, Fq>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let p = BigUint::from_str_radix(&Fq::MODULUS[2..], 16).unwrap();
        FpChip::configure(
            meta,
            FpStrategy::Simple,
            &[NUM_ADVICE],
            &[NUM_LOOKUP_ADVICE],
            NUM_FIXED,
            LOOKUP_BITS,
            LIMB_BITS,
            NUM_LIMBS,
            p,
            0,
            K,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let fp_chip = config;
        let flex_chip = fp_chip.gate();
        fp_chip.load_lookup_table(&mut layouter)?;
        let fp2_chip = Fp2Chip::construct(&fp_chip);

        layouter.assign_region(
            || "my region",
            |region| {
                let ctx = &mut Context::new(
                    region,
                    ContextParams {
                        max_rows: fp_chip.range.gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: fp_chip.range.gate.constants.clone(),
                    },
                );

                let u = Fq2 {
                    c0: Fq::from(5),
                    c1: Fq::from(7),
                };
                let u = fp2_chip.load_constant(ctx, u);

                let ec_point = map_to_curve(ctx, &flex_chip, &fp_chip, &fp2_chip, &u);

                assert_eq(
                    &ec_point.x,
                    "21300161304548986609524245515402346087899144942671434135620162144927701862095",
                    "14780309652284711482718429692162845108298299581354696723664233575735346851474",
                    NUM_LIMBS,
                    LIMB_BITS,
                );

                assert_eq(
                    &ec_point.y,
                    "2310029328200981368661573722065505484941106134328264115005708776222531260377",
                    "20321677324631579761093161361429217733103182689966671776450427050072304349311",
                    NUM_LIMBS,
                    LIMB_BITS,
                );

                Ok(())
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // use crate::utils::{gen_pk, gen_proof, gen_srs};

    use halo2_base::halo2_proofs::dev::MockProver;

    use super::*;

    #[test]
    fn test_map_to_curve() {
        let circuit = MyCircuit;

        MockProver::run(K as u32, &circuit, vec![])
            .unwrap()
            .assert_satisfied();

        // let params = gen_srs(K as u32);
        // let pk = gen_pk(&params, &circuit);
        // let now = Instant::now();
        // gen_proof(K, &params, &pk, circuit, vec![]);
        // println!("{} ms", now.elapsed().as_millis());
    }
}
