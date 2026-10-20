//! Windows 3.1 index queries must fail before a later host value is returned.

use super::super::test_support::{NoHost, tiny_ne_executable};
use crate::Runtime;

#[test]
fn system_metrics_outside_win31_return_zero_without_the_host() {
    let mut host = NoHost;
    // Index 43 is `SM_CMETRICS` in Windows 3.1 and `SM_CMOUSEBUTTONS` on a
    // later host. `SM_SECURE` (44) and `SM_CXSMICON` (49) are later indexes.
    // None of them query the host, so its value is not the guest result.
    assert_eq!(super::system_metrics(&mut host, -1).unwrap(), 0);
    assert_eq!(super::system_metrics(&mut host, 43).unwrap(), 0);
    assert_eq!(super::system_metrics(&mut host, 44).unwrap(), 0);
    assert_eq!(super::system_metrics(&mut host, 49).unwrap(), 0);
    assert_eq!(super::system_metrics(&mut host, i16::MAX).unwrap(), 0);
    // SM_CXSCREEN and SM_DBCSENABLED still query the host.
    assert!(super::system_metrics(&mut host, 0).is_err());
    assert!(super::system_metrics(&mut host, 42).is_err());
}

#[test]
fn stock_object_outside_win31_returns_null_without_the_host() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\STOCK.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let mut host = NoHost;
    // Index 9 is unused. DEFAULT_GUI_FONT, DC_BRUSH, and DC_PEN are later.
    for index in [-1, 9, 17, 18, 19] {
        assert_eq!(
            state.get_stock_object(index, &mut host).unwrap(),
            0,
            "{index}"
        );
    }
    // WHITE_BRUSH and SYSTEM_FIXED_FONT still query the host.
    assert!(state.get_stock_object(0, &mut host).is_err());
    assert!(state.get_stock_object(16, &mut host).is_err());
}
