// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ml")]

#[test]
fn patched_candle_preserves_stored_numpy_and_pytorch_archive_reading() -> candle_core::Result<()> {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/candle-core/tests");
    let arrays = candle_core::Tensor::read_npz(fixtures.join("test.npz"))?;
    assert_eq!(arrays.len(), 2);
    assert_eq!(arrays[0].0, "x");
    assert_eq!(
        arrays[0]
            .1
            .to_dtype(candle_core::DType::U8)?
            .to_vec1::<u8>()?,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    );
    let indexed = candle_core::npy::NpzTensors::new(fixtures.join("test.npz"))?;
    assert_eq!(
        indexed
            .get("x_plus_one")?
            .unwrap()
            .to_dtype(candle_core::DType::U8)?
            .to_vec1::<u8>()?,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    );
    let tensors = candle_core::pickle::read_pth_tensor_info(
        fixtures.join("fortran_tensor_3d.pth"),
        false,
        None,
    )?;
    assert_eq!(tensors.len(), 1);
    assert_eq!(tensors[0].name, "tensor_fortran");
    Ok(())
}
