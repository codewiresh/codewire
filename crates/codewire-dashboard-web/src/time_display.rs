/// Format a Unix timestamp as the stable English date used by the legacy
/// dashboard without adding a browser/runtime locale dependency.
pub(crate) fn calendar_date(seconds: i64) -> String {
    let (year, month, day) = civil_date(seconds.div_euclid(86_400));
    format!("{} {day}, {year}", month_name(month))
}

pub(crate) fn calendar_datetime(seconds: i64) -> String {
    let (year, month, day) = civil_date(seconds.div_euclid(86_400));
    let seconds_in_day = seconds.rem_euclid(86_400);
    let hour = seconds_in_day / 3_600;
    let minute = seconds_in_day % 3_600 / 60;
    format!(
        "{} {day}, {year}, {hour:02}:{minute:02} UTC",
        month_name(month)
    )
}

// Howard Hinnant's civil-from-days algorithm, adapted to an epoch-day input.
fn civil_date(days_since_epoch: i64) -> (i64, u32, u32) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_piece = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_piece + 2) / 5 + 1;
    let month = month_piece + if month_piece < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}

fn month_name(month: u32) -> &'static str {
    match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_timestamps_have_stable_english_display_values() {
        assert_eq!(calendar_date(0), "Jan 1, 1970");
        assert_eq!(calendar_date(1_704_067_200), "Jan 1, 2024");
        assert_eq!(calendar_datetime(1_704_112_140), "Jan 1, 2024, 12:29 UTC");
        assert_eq!(calendar_datetime(-60), "Dec 31, 1969, 23:59 UTC");
    }
}
