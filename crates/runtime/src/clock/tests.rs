use super::*;

#[test]
fn short_clock_samples_retain_their_fractional_ticks() {
    let mut clock = DeviceClock::new();
    let mut ticks = 0;
    for _ in 0..1_000 {
        ticks += clock.ticks_for(Duration::from_micros(1_000));
    }
    assert_eq!(ticks, PIT_HZ as u64);
    assert_eq!(clock.fractional_tick, 0);
}

#[test]
fn zero_elapsed_time_does_not_advance_or_discard_fraction() {
    let mut clock = DeviceClock::new();
    assert_eq!(clock.ticks_for(Duration::from_nanos(1)), 0);
    let fraction = clock.fractional_tick;
    assert_eq!(clock.ticks_for(Duration::ZERO), 0);
    assert_eq!(clock.fractional_tick, fraction);
}
