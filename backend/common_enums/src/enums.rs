use std::num::ParseFloatError;
use utoipa::ToSchema;

// Conversion functions for compatibility with hyperswitch_api_models
impl TryFrom<CardNetwork> for hyperswitch_api_models::enums::CardNetwork {
    type Error = &'static str;

    fn try_from(network: CardNetwork) -> Result<Self, Self::Error> {
        match network {
            CardNetwork::Visa => Ok(Self::Visa),
            CardNetwork::Mastercard => Ok(Self::Mastercard),
            CardNetwork::AmericanExpress => Ok(Self::AmericanExpress),
            CardNetwork::JCB => Ok(Self::JCB),
            CardNetwork::DinersClub => Ok(Self::DinersClub),
            CardNetwork::Discover => Ok(Self::Discover),
            CardNetwork::CartesBancaires => Ok(Self::CartesBancaires),
            CardNetwork::UnionPay => Ok(Self::UnionPay),
            CardNetwork::Interac => Ok(Self::Interac),
            CardNetwork::RuPay => Ok(Self::RuPay),
            CardNetwork::Maestro => Ok(Self::Maestro),
            // US local networks - these might not exist in hyperswitch_api_models
            CardNetwork::Star => Err("Star network not supported in hyperswitch_api_models"),
            CardNetwork::Pulse => Err("Pulse network not supported in hyperswitch_api_models"),
            CardNetwork::Accel => Err("Accel network not supported in hyperswitch_api_models"),
            CardNetwork::Nyce => Err("Nyce network not supported in hyperswitch_api_models"),
        }
    }
}

impl From<CountryAlpha2> for hyperswitch_api_models::enums::CountryAlpha2 {
    fn from(country: CountryAlpha2) -> Self {
        match country {
            CountryAlpha2::US => Self::US,
            CountryAlpha2::AF => Self::AF,
            CountryAlpha2::AX => Self::AX,
            CountryAlpha2::AL => Self::AL,
            CountryAlpha2::DZ => Self::DZ,
            CountryAlpha2::AS => Self::AS,
            CountryAlpha2::AD => Self::AD,
            CountryAlpha2::AO => Self::AO,
            CountryAlpha2::AI => Self::AI,
            CountryAlpha2::AQ => Self::AQ,
            CountryAlpha2::AG => Self::AG,
            CountryAlpha2::AR => Self::AR,
            CountryAlpha2::AM => Self::AM,
            CountryAlpha2::AW => Self::AW,
            CountryAlpha2::AU => Self::AU,
            CountryAlpha2::AT => Self::AT,
            CountryAlpha2::AZ => Self::AZ,
            CountryAlpha2::BS => Self::BS,
            CountryAlpha2::BH => Self::BH,
            CountryAlpha2::BD => Self::BD,
            CountryAlpha2::BB => Self::BB,
            CountryAlpha2::BY => Self::BY,
            CountryAlpha2::BE => Self::BE,
            CountryAlpha2::BZ => Self::BZ,
            CountryAlpha2::BJ => Self::BJ,
            CountryAlpha2::BM => Self::BM,
            CountryAlpha2::BT => Self::BT,
            CountryAlpha2::BO => Self::BO,
            CountryAlpha2::BQ => Self::BQ,
            CountryAlpha2::BA => Self::BA,
            CountryAlpha2::BW => Self::BW,
            CountryAlpha2::BV => Self::BV,
            CountryAlpha2::BR => Self::BR,
            CountryAlpha2::IO => Self::IO,
            CountryAlpha2::BN => Self::BN,
            CountryAlpha2::BG => Self::BG,
            CountryAlpha2::BF => Self::BF,
            CountryAlpha2::BI => Self::BI,
            CountryAlpha2::KH => Self::KH,
            CountryAlpha2::CM => Self::CM,
            CountryAlpha2::CA => Self::CA,
            CountryAlpha2::CV => Self::CV,
            CountryAlpha2::KY => Self::KY,
            CountryAlpha2::CF => Self::CF,
            CountryAlpha2::TD => Self::TD,
            CountryAlpha2::CL => Self::CL,
            CountryAlpha2::CN => Self::CN,
            CountryAlpha2::CX => Self::CX,
            CountryAlpha2::CC => Self::CC,
            CountryAlpha2::CO => Self::CO,
            CountryAlpha2::KM => Self::KM,
            CountryAlpha2::CG => Self::CG,
            CountryAlpha2::CD => Self::CD,
            CountryAlpha2::CK => Self::CK,
            CountryAlpha2::CR => Self::CR,
            CountryAlpha2::CI => Self::CI,
            CountryAlpha2::HR => Self::HR,
            CountryAlpha2::CU => Self::CU,
            CountryAlpha2::CW => Self::CW,
            CountryAlpha2::CY => Self::CY,
            CountryAlpha2::CZ => Self::CZ,
            CountryAlpha2::DK => Self::DK,
            CountryAlpha2::DJ => Self::DJ,
            CountryAlpha2::DM => Self::DM,
            CountryAlpha2::DO => Self::DO,
            CountryAlpha2::EC => Self::EC,
            CountryAlpha2::EG => Self::EG,
            CountryAlpha2::SV => Self::SV,
            CountryAlpha2::GQ => Self::GQ,
            CountryAlpha2::ER => Self::ER,
            CountryAlpha2::EE => Self::EE,
            CountryAlpha2::ET => Self::ET,
            CountryAlpha2::FK => Self::FK,
            CountryAlpha2::FO => Self::FO,
            CountryAlpha2::FJ => Self::FJ,
            CountryAlpha2::FI => Self::FI,
            CountryAlpha2::FR => Self::FR,
            CountryAlpha2::GF => Self::GF,
            CountryAlpha2::PF => Self::PF,
            CountryAlpha2::TF => Self::TF,
            CountryAlpha2::GA => Self::GA,
            CountryAlpha2::GM => Self::GM,
            CountryAlpha2::GE => Self::GE,
            CountryAlpha2::DE => Self::DE,
            CountryAlpha2::GH => Self::GH,
            CountryAlpha2::GI => Self::GI,
            CountryAlpha2::GR => Self::GR,
            CountryAlpha2::GL => Self::GL,
            CountryAlpha2::GD => Self::GD,
            CountryAlpha2::GP => Self::GP,
            CountryAlpha2::GU => Self::GU,
            CountryAlpha2::GT => Self::GT,
            CountryAlpha2::GG => Self::GG,
            CountryAlpha2::GN => Self::GN,
            CountryAlpha2::GW => Self::GW,
            CountryAlpha2::GY => Self::GY,
            CountryAlpha2::HT => Self::HT,
            CountryAlpha2::HM => Self::HM,
            CountryAlpha2::VA => Self::VA,
            CountryAlpha2::HN => Self::HN,
            CountryAlpha2::HK => Self::HK,
            CountryAlpha2::HU => Self::HU,
            CountryAlpha2::IS => Self::IS,
            CountryAlpha2::IN => Self::IN,
            CountryAlpha2::ID => Self::ID,
            CountryAlpha2::IR => Self::IR,
            CountryAlpha2::IQ => Self::IQ,
            CountryAlpha2::IE => Self::IE,
            CountryAlpha2::IM => Self::IM,
            CountryAlpha2::IL => Self::IL,
            CountryAlpha2::IT => Self::IT,
            CountryAlpha2::JM => Self::JM,
            CountryAlpha2::JP => Self::JP,
            CountryAlpha2::JE => Self::JE,
            CountryAlpha2::JO => Self::JO,
            CountryAlpha2::KZ => Self::KZ,
            CountryAlpha2::KE => Self::KE,
            CountryAlpha2::KI => Self::KI,
            CountryAlpha2::KP => Self::KP,
            CountryAlpha2::KR => Self::KR,
            CountryAlpha2::KW => Self::KW,
            CountryAlpha2::KG => Self::KG,
            CountryAlpha2::LA => Self::LA,
            CountryAlpha2::LV => Self::LV,
            CountryAlpha2::LB => Self::LB,
            CountryAlpha2::LS => Self::LS,
            CountryAlpha2::LR => Self::LR,
            CountryAlpha2::LY => Self::LY,
            CountryAlpha2::LI => Self::LI,
            CountryAlpha2::LT => Self::LT,
            CountryAlpha2::LU => Self::LU,
            CountryAlpha2::MO => Self::MO,
            CountryAlpha2::MK => Self::MK,
            CountryAlpha2::MG => Self::MG,
            CountryAlpha2::MW => Self::MW,
            CountryAlpha2::MY => Self::MY,
            CountryAlpha2::MV => Self::MV,
            CountryAlpha2::ML => Self::ML,
            CountryAlpha2::MT => Self::MT,
            CountryAlpha2::MH => Self::MH,
            CountryAlpha2::MQ => Self::MQ,
            CountryAlpha2::MR => Self::MR,
            CountryAlpha2::MU => Self::MU,
            CountryAlpha2::YT => Self::YT,
            CountryAlpha2::MX => Self::MX,
            CountryAlpha2::FM => Self::FM,
            CountryAlpha2::MD => Self::MD,
            CountryAlpha2::MC => Self::MC,
            CountryAlpha2::MN => Self::MN,
            CountryAlpha2::ME => Self::ME,
            CountryAlpha2::MS => Self::MS,
            CountryAlpha2::MA => Self::MA,
            CountryAlpha2::MZ => Self::MZ,
            CountryAlpha2::MM => Self::MM,
            CountryAlpha2::NA => Self::NA,
            CountryAlpha2::NR => Self::NR,
            CountryAlpha2::NP => Self::NP,
            CountryAlpha2::NL => Self::NL,
            CountryAlpha2::NC => Self::NC,
            CountryAlpha2::NZ => Self::NZ,
            CountryAlpha2::NI => Self::NI,
            CountryAlpha2::NE => Self::NE,
            CountryAlpha2::NG => Self::NG,
            CountryAlpha2::NU => Self::NU,
            CountryAlpha2::NF => Self::NF,
            CountryAlpha2::MP => Self::MP,
            CountryAlpha2::NO => Self::NO,
            CountryAlpha2::OM => Self::OM,
            CountryAlpha2::PK => Self::PK,
            CountryAlpha2::PW => Self::PW,
            CountryAlpha2::PS => Self::PS,
            CountryAlpha2::PA => Self::PA,
            CountryAlpha2::PG => Self::PG,
            CountryAlpha2::PY => Self::PY,
            CountryAlpha2::PE => Self::PE,
            CountryAlpha2::PH => Self::PH,
            CountryAlpha2::PN => Self::PN,
            CountryAlpha2::PL => Self::PL,
            CountryAlpha2::PT => Self::PT,
            CountryAlpha2::PR => Self::PR,
            CountryAlpha2::QA => Self::QA,
            CountryAlpha2::RE => Self::RE,
            CountryAlpha2::RO => Self::RO,
            CountryAlpha2::RU => Self::RU,
            CountryAlpha2::RW => Self::RW,
            CountryAlpha2::BL => Self::BL,
            CountryAlpha2::SH => Self::SH,
            CountryAlpha2::KN => Self::KN,
            CountryAlpha2::LC => Self::LC,
            CountryAlpha2::MF => Self::MF,
            CountryAlpha2::PM => Self::PM,
            CountryAlpha2::VC => Self::VC,
            CountryAlpha2::WS => Self::WS,
            CountryAlpha2::SM => Self::SM,
            CountryAlpha2::ST => Self::ST,
            CountryAlpha2::SA => Self::SA,
            CountryAlpha2::SN => Self::SN,
            CountryAlpha2::RS => Self::RS,
            CountryAlpha2::SC => Self::SC,
            CountryAlpha2::SL => Self::SL,
            CountryAlpha2::SG => Self::SG,
            CountryAlpha2::SX => Self::SX,
            CountryAlpha2::SK => Self::SK,
            CountryAlpha2::SI => Self::SI,
            CountryAlpha2::SB => Self::SB,
            CountryAlpha2::SO => Self::SO,
            CountryAlpha2::ZA => Self::ZA,
            CountryAlpha2::GS => Self::GS,
            CountryAlpha2::SS => Self::SS,
            CountryAlpha2::ES => Self::ES,
            CountryAlpha2::LK => Self::LK,
            CountryAlpha2::SD => Self::SD,
            CountryAlpha2::SR => Self::SR,
            CountryAlpha2::SJ => Self::SJ,
            CountryAlpha2::SZ => Self::SZ,
            CountryAlpha2::SE => Self::SE,
            CountryAlpha2::CH => Self::CH,
            CountryAlpha2::SY => Self::SY,
            CountryAlpha2::TW => Self::TW,
            CountryAlpha2::TJ => Self::TJ,
            CountryAlpha2::TZ => Self::TZ,
            CountryAlpha2::TH => Self::TH,
            CountryAlpha2::TL => Self::TL,
            CountryAlpha2::TG => Self::TG,
            CountryAlpha2::TK => Self::TK,
            CountryAlpha2::TO => Self::TO,
            CountryAlpha2::TT => Self::TT,
            CountryAlpha2::TN => Self::TN,
            CountryAlpha2::TR => Self::TR,
            CountryAlpha2::TM => Self::TM,
            CountryAlpha2::TC => Self::TC,
            CountryAlpha2::TV => Self::TV,
            CountryAlpha2::UG => Self::UG,
            CountryAlpha2::UA => Self::UA,
            CountryAlpha2::AE => Self::AE,
            CountryAlpha2::GB => Self::GB,
            CountryAlpha2::UM => Self::UM,
            CountryAlpha2::UY => Self::UY,
            CountryAlpha2::UZ => Self::UZ,
            CountryAlpha2::VU => Self::VU,
            CountryAlpha2::VE => Self::VE,
            CountryAlpha2::VN => Self::VN,
            CountryAlpha2::VG => Self::VG,
            CountryAlpha2::VI => Self::VI,
            CountryAlpha2::WF => Self::WF,
            CountryAlpha2::EH => Self::EH,
            CountryAlpha2::YE => Self::YE,
            CountryAlpha2::ZM => Self::ZM,
            CountryAlpha2::ZW => Self::ZW,
        }
    }
}

/// The three-letter ISO 4217 currency code (e.g., "USD", "EUR") for the payment amount. This field is mandatory for creating a payment.
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::VariantNames,
    ToSchema,
)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum Currency {
    AED,
    AFN,
    ALL,
    AMD,
    ANG,
    AOA,
    ARS,
    AUD,
    AWG,
    AZN,
    BAM,
    BBD,
    BDT,
    BGN,
    BHD,
    BIF,
    BMD,
    BND,
    BOB,
    BRL,
    BSD,
    BTN,
    BWP,
    BYN,
    BZD,
    CAD,
    CDF,
    CHF,
    CLF,
    CLP,
    CNY,
    COP,
    CRC,
    CUC,
    CUP,
    CVE,
    CZK,
    DJF,
    DKK,
    DOP,
    DZD,
    EGP,
    ERN,
    ETB,
    EUR,
    FJD,
    FKP,
    GBP,
    GEL,
    GHS,
    GIP,
    GMD,
    GNF,
    GTQ,
    GYD,
    HKD,
    HNL,
    HRK,
    HTG,
    HUF,
    IDR,
    ILS,
    INR,
    IQD,
    IRR,
    ISK,
    JMD,
    JOD,
    JPY,
    KES,
    KGS,
    KHR,
    KMF,
    KPW,
    KRW,
    KWD,
    KYD,
    KZT,
    LAK,
    LBP,
    LKR,
    LRD,
    LSL,
    LYD,
    MAD,
    MDL,
    MGA,
    MKD,
    MMK,
    MNT,
    MOP,
    MRU,
    MUR,
    MVR,
    MWK,
    MXN,
    MYR,
    MZN,
    NAD,
    NGN,
    NIO,
    NOK,
    NPR,
    NZD,
    OMR,
    PAB,
    PEN,
    PGK,
    PHP,
    PKR,
    PLN,
    PYG,
    QAR,
    RON,
    RSD,
    RUB,
    RWF,
    SAR,
    SBD,
    SCR,
    SDG,
    SEK,
    SGD,
    SHP,
    SLE,
    SLL,
    SOS,
    SRD,
    SSP,
    STD,
    STN,
    SVC,
    SYP,
    SZL,
    THB,
    TJS,
    TMT,
    TND,
    TOP,
    TRY,
    TTD,
    TWD,
    TZS,
    UAH,
    UGX,
    #[default]
    USD,
    UYU,
    UZS,
    VES,
    VND,
    VUV,
    WST,
    XAF,
    XCD,
    XOF,
    XPF,
    YER,
    ZAR,
    ZMW,
    ZWL,
}

/// Specifies the regulated name for a card network, primarily used for US debit card routing regulations.
/// This helps identify specific regulatory categories that cards may fall under.
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RegulatedName {
    #[serde(rename = "GOVERNMENT NON-EXEMPT INTERCHANGE FEE (WITH FRAUD)")]
    #[strum(serialize = "GOVERNMENT NON-EXEMPT INTERCHANGE FEE (WITH FRAUD)")]
    NonExemptWithFraud,

    #[serde(untagged)]
    #[strum(default)]
    Unknown(String),
}

impl Currency {
    pub fn to_currency_base_unit(self, amount: i64) -> Result<String, std::convert::Infallible> {
        let amount_f64 = self.to_currency_base_unit_asf64(amount)?;
        Ok(format!("{amount_f64:.2}"))
    }

    pub fn to_currency_base_unit_asf64(self, amount: i64) -> Result<f64, std::convert::Infallible> {
        let exponent = self.number_of_digits_after_decimal_point();
        let divisor = 10_u32.pow(exponent.into());
        let amount_f64 = amount as f64 / f64::from(divisor);
        Ok(amount_f64)
    }

    pub fn to_currency_lower_unit(self, amount: String) -> Result<String, ParseFloatError> {
        let amount_decimal = amount.parse::<f64>()?;
        let exponent = self.number_of_digits_after_decimal_point();
        let multiplier = 10_u32.pow(exponent.into());
        let final_amount = amount_decimal * f64::from(multiplier);
        Ok(final_amount.to_string())
    }

    pub fn to_currency_base_unit_with_zero_decimal_check(
        self,
        amount: i64,
    ) -> Result<String, std::convert::Infallible> {
        if self.is_zero_decimal_currency() {
            Ok(amount.to_string())
        } else {
            self.to_currency_base_unit(amount)
        }
    }

    pub fn iso_4217(self) -> &'static str {
        match self {
            Self::AED => "784",
            Self::AFN => "971",
            Self::ALL => "008",
            Self::AMD => "051",
            Self::ANG => "532",
            Self::AOA => "973",
            Self::ARS => "032",
            Self::AUD => "036",
            Self::AWG => "533",
            Self::AZN => "944",
            Self::BAM => "977",
            Self::BBD => "052",
            Self::BDT => "050",
            Self::BGN => "975",
            Self::BHD => "048",
            Self::BIF => "108",
            Self::BMD => "060",
            Self::BND => "096",
            Self::BOB => "068",
            Self::BRL => "986",
            Self::BSD => "044",
            Self::BTN => "064",
            Self::BWP => "072",
            Self::BYN => "933",
            Self::BZD => "084",
            Self::CAD => "124",
            Self::CDF => "976",
            Self::CHF => "756",
            Self::CLF => "990",
            Self::CLP => "152",
            Self::CNY => "156",
            Self::COP => "170",
            Self::CRC => "188",
            Self::CUC => "931",
            Self::CUP => "192",
            Self::CVE => "132",
            Self::CZK => "203",
            Self::DJF => "262",
            Self::DKK => "208",
            Self::DOP => "214",
            Self::DZD => "012",
            Self::EGP => "818",
            Self::ERN => "232",
            Self::ETB => "230",
            Self::EUR => "978",
            Self::FJD => "242",
            Self::FKP => "238",
            Self::GBP => "826",
            Self::GEL => "981",
            Self::GHS => "936",
            Self::GIP => "292",
            Self::GMD => "270",
            Self::GNF => "324",
            Self::GTQ => "320",
            Self::GYD => "328",
            Self::HKD => "344",
            Self::HNL => "340",
            Self::HRK => "191",
            Self::HTG => "332",
            Self::HUF => "348",
            Self::IDR => "360",
            Self::ILS => "376",
            Self::INR => "356",
            Self::IQD => "368",
            Self::IRR => "364",
            Self::ISK => "352",
            Self::JMD => "388",
            Self::JOD => "400",
            Self::JPY => "392",
            Self::KES => "404",
            Self::KGS => "417",
            Self::KHR => "116",
            Self::KMF => "174",
            Self::KPW => "408",
            Self::KRW => "410",
            Self::KWD => "414",
            Self::KYD => "136",
            Self::KZT => "398",
            Self::LAK => "418",
            Self::LBP => "422",
            Self::LKR => "144",
            Self::LRD => "430",
            Self::LSL => "426",
            Self::LYD => "434",
            Self::MAD => "504",
            Self::MDL => "498",
            Self::MGA => "969",
            Self::MKD => "807",
            Self::MMK => "104",
            Self::MNT => "496",
            Self::MOP => "446",
            Self::MRU => "929",
            Self::MUR => "480",
            Self::MVR => "462",
            Self::MWK => "454",
            Self::MXN => "484",
            Self::MYR => "458",
            Self::MZN => "943",
            Self::NAD => "516",
            Self::NGN => "566",
            Self::NIO => "558",
            Self::NOK => "578",
            Self::NPR => "524",
            Self::NZD => "554",
            Self::OMR => "512",
            Self::PAB => "590",
            Self::PEN => "604",
            Self::PGK => "598",
            Self::PHP => "608",
            Self::PKR => "586",
            Self::PLN => "985",
            Self::PYG => "600",
            Self::QAR => "634",
            Self::RON => "946",
            Self::RSD => "941",
            Self::RUB => "643",
            Self::RWF => "646",
            Self::SAR => "682",
            Self::SBD => "090",
            Self::SCR => "690",
            Self::SDG => "938",
            Self::SEK => "752",
            Self::SGD => "702",
            Self::SHP => "654",
            Self::SLE => "925",
            Self::SLL => "694",
            Self::SOS => "706",
            Self::SRD => "968",
            Self::SSP => "728",
            Self::STD => "678",
            Self::STN => "930",
            Self::SVC => "222",
            Self::SYP => "760",
            Self::SZL => "748",
            Self::THB => "764",
            Self::TJS => "972",
            Self::TMT => "934",
            Self::TND => "788",
            Self::TOP => "776",
            Self::TRY => "949",
            Self::TTD => "780",
            Self::TWD => "901",
            Self::TZS => "834",
            Self::UAH => "980",
            Self::UGX => "800",
            Self::USD => "840",
            Self::UYU => "858",
            Self::UZS => "860",
            Self::VES => "928",
            Self::VND => "704",
            Self::VUV => "548",
            Self::WST => "882",
            Self::XAF => "950",
            Self::XCD => "951",
            Self::XOF => "952",
            Self::XPF => "953",
            Self::YER => "886",
            Self::ZAR => "710",
            Self::ZMW => "967",
            Self::ZWL => "932",
        }
    }

    pub fn is_zero_decimal_currency(self) -> bool {
        matches!(
            self,
            Self::BIF
                | Self::CLP
                | Self::DJF
                | Self::GNF
                | Self::JPY
                | Self::KMF
                | Self::KRW
                | Self::MGA
                | Self::PYG
                | Self::RWF
                | Self::UGX
                | Self::VND
                | Self::VUV
                | Self::XAF
                | Self::XOF
                | Self::XPF
        )
    }

    pub fn is_three_decimal_currency(self) -> bool {
        matches!(
            self,
            Self::BHD | Self::JOD | Self::KWD | Self::OMR | Self::TND
        )
    }

    pub fn is_four_decimal_currency(self) -> bool {
        matches!(self, Self::CLF)
    }

    pub fn number_of_digits_after_decimal_point(self) -> u8 {
        if self.is_zero_decimal_currency() {
            0
        } else if self.is_three_decimal_currency() {
            3
        } else if self.is_four_decimal_currency() {
            4
        } else {
            2
        }
    }
}

/// Specifies how the payment is captured.
/// - `automatic`: Funds are captured immediately after successful authorization. This is the default behavior if the field is omitted.
/// - `manual`: Funds are authorized but not captured. A separate request to the `/payments/{payment_id}/capture` endpoint is required to capture the funds.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::VariantNames,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum CaptureMethod {
    #[default]
    Automatic,
    Manual,
    ManualMultiple,
    Scheduled,
    SequentialAutomatic,
}

/// Specifies how the payment method can be used for future payments.
/// - `off_session`: The payment method can be used for future payments when the customer is not present.
/// - `on_session`: The payment method is intended for use only when the customer is present during checkout.
/// If omitted, defaults to `on_session`.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::VariantNames,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum FutureUsage {
    OffSession,
    #[default]
    OnSession,
}

/// To indicate the type of payment experience that the customer would go through
#[derive(
    Eq,
    strum::EnumString,
    PartialEq,
    Hash,
    Copy,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    strum::Display,
    ToSchema,
    Default,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PaymentExperience {
    #[default]
    RedirectToUrl,
    InvokeSdkClient,
    DisplayQrCode,
    OneClick,
    LinkWallet,
    InvokePaymentApp,
    DisplayWaitScreen,
    CollectOtp,
}

/// Indicates the sub type of payment method. Eg: 'google_pay' & 'apple_pay' for wallets.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::VariantNames,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PaymentMethodType {
    Ach,
    Affirm,
    AfterpayClearpay,
    Alfamart,
    AliPay,
    AliPayHk,
    Alma,
    AmazonPay,
    ApplePay,
    Atome,
    Bacs,
    BancontactCard,
    Becs,
    Benefit,
    Bizum,
    Blik,
    Boleto,
    BcaBankTransfer,
    BniVa,
    BriVa,
    CardRedirect,
    CimbVa,
    #[serde(rename = "classic")]
    ClassicReward,
    Credit,
    CryptoCurrency,
    Cashapp,
    Dana,
    DanamonVa,
    Debit,
    DuitNow,
    Efecty,
    Eft,
    Eps,
    Fps,
    Evoucher,
    Giropay,
    Givex,
    GooglePay,
    GoPay,
    Gcash,
    Ideal,
    Interac,
    Indomaret,
    Klarna,
    KakaoPay,
    LocalBankRedirect,
    MandiriVa,
    Knet,
    MbWay,
    MobilePay,
    Momo,
    MomoAtm,
    Multibanco,
    OnlineBankingThailand,
    OnlineBankingCzechRepublic,
    OnlineBankingFinland,
    OnlineBankingFpx,
    OnlineBankingPoland,
    OnlineBankingSlovakia,
    Oxxo,
    PagoEfectivo,
    PermataBankTransfer,
    OpenBankingUk,
    PayBright,
    Paypal,
    Paze,
    Pix,
    PaySafeCard,
    Przelewy24,
    PromptPay,
    Pse,
    RedCompra,
    RedPagos,
    SamsungPay,
    Sepa,
    SepaBankTransfer,
    Sofort,
    Swish,
    TouchNGo,
    Trustly,
    Twint,
    UpiCollect,
    UpiIntent,
    Vipps,
    VietQr,
    Venmo,
    Walley,
    WeChatPay,
    SevenEleven,
    Lawson,
    MiniStop,
    FamilyMart,
    Seicomart,
    PayEasy,
    LocalBankTransfer,
    Mifinity,
    #[serde(rename = "open_banking_pis")]
    OpenBankingPIS,
    DirectCarrierBilling,
    InstantBankTransfer,
    InstantBankTransferFinland,
    InstantBankTransferPoland,
    RevolutPay,
}

impl PaymentMethodType {
    pub fn should_check_for_customer_saved_payment_method_type(self) -> bool {
        match self {
            Self::Credit | Self::Debit => true,
            _ => false,
        }
    }

    pub fn to_display_name(&self) -> String {
        match self {
            Self::ApplePay => "Apple Pay".to_string(),
            Self::GooglePay => "Google Pay".to_string(),
            Self::SamsungPay => "Samsung Pay".to_string(),
            Self::AliPay => "AliPay".to_string(),
            Self::WeChatPay => "WeChat Pay".to_string(),
            Self::KakaoPay => "Kakao Pay".to_string(),
            Self::GoPay => "GoPay".to_string(),
            Self::Gcash => "GCash".to_string(),
            _ => format!("{self:?}"),
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    serde::Serialize,
    serde::Deserialize,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RefundStatus {
    #[serde(alias = "Failure")]
    Failure,
    #[serde(alias = "ManualReview")]
    ManualReview,
    #[default]
    #[serde(alias = "Pending")]
    Pending,
    #[serde(alias = "Success")]
    Success,
    #[serde(alias = "TransactionFailure")]
    TransactionFailure,
}

/// The status of the attempt
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Hash,
    Eq,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AttemptStatus {
    Started,
    AuthenticationFailed,
    RouterDeclined,
    AuthenticationPending,
    AuthenticationSuccessful,
    Authorized,
    AuthorizationFailed,
    Charged,
    Authorizing,
    CodInitiated,
    Voided,
    VoidInitiated,
    CaptureInitiated,
    CaptureFailed,
    VoidFailed,
    AutoRefunded,
    PartialCharged,
    PartialChargedAndChargeable,
    Unresolved,
    #[default]
    Pending,
    Failure,
    PaymentMethodAwaited,
    ConfirmationAwaited,
    DeviceDataCollectionPending,
    IntegrityFailure,
}

impl AttemptStatus {
    pub fn is_terminal_status(self) -> bool {
        matches!(
            self,
            Self::Charged
                | Self::AutoRefunded
                | Self::Voided
                | Self::PartialCharged
                | Self::AuthenticationFailed
                | Self::AuthorizationFailed
                | Self::VoidFailed
                | Self::CaptureFailed
                | Self::Failure
                | Self::IntegrityFailure
        )
    }
}

/// Status of the dispute
#[derive(
    Clone,
    Debug,
    Copy,
    Default,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DisputeStatus {
    #[default]
    DisputeOpened,
    DisputeExpired,
    DisputeAccepted,
    DisputeCancelled,
    DisputeChallenged,
    DisputeWon,
    DisputeLost,
}

/// Stage of the dispute
#[derive(
    Clone,
    Copy,
    Default,
    Debug,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DisputeStage {
    PreDispute,
    #[default]
    Dispute,
    PreArbitration,
}

/// Indicates the card network.
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::VariantNames,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
pub enum CardNetwork {
    #[serde(alias = "VISA")]
    Visa,
    #[serde(alias = "MASTERCARD")]
    Mastercard,
    #[serde(alias = "AMERICANEXPRESS")]
    #[serde(alias = "AMEX")]
    AmericanExpress,
    JCB,
    #[serde(alias = "DINERSCLUB")]
    DinersClub,
    #[serde(alias = "DISCOVER")]
    Discover,
    #[serde(alias = "CARTESBANCAIRES")]
    CartesBancaires,
    #[serde(alias = "UNIONPAY")]
    UnionPay,
    #[serde(alias = "INTERAC")]
    Interac,
    #[serde(alias = "RUPAY")]
    RuPay,
    #[serde(alias = "MAESTRO")]
    Maestro,
    #[serde(alias = "STAR")]
    Star,
    #[serde(alias = "PULSE")]
    Pulse,
    #[serde(alias = "ACCEL")]
    Accel,
    #[serde(alias = "NYCE")]
    Nyce,
}

impl CardNetwork {
    pub fn is_global_network(&self) -> bool {
        matches!(
            self,
            Self::Visa
                | Self::Mastercard
                | Self::AmericanExpress
                | Self::JCB
                | Self::DinersClub
                | Self::Discover
                | Self::CartesBancaires
                | Self::UnionPay
        )
    }

    pub fn is_us_local_network(&self) -> bool {
        matches!(self, Self::Star | Self::Pulse | Self::Accel | Self::Nyce)
    }
}

/// Indicates the type of payment method. Eg: 'card', 'wallet', etc.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::VariantNames,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PaymentMethod {
    #[default]
    Card,
    CardRedirect,
    PayLater,
    Wallet,
    BankRedirect,
    BankTransfer,
    Crypto,
    BankDebit,
    Reward,
    RealTimePayment,
    Upi,
    Voucher,
    GiftCard,
    OpenBanking,
    MobilePayment,
}

/// Specifies the type of cardholder authentication to be applied for a payment.
///
/// - `ThreeDs`: Requests 3D Secure (3DS) authentication. If the card is enrolled, 3DS authentication will be activated, potentially shifting chargeback liability to the issuer.
/// - `NoThreeDs`: Indicates that 3D Secure authentication should not be performed. The liability for chargebacks typically remains with the merchant. This is often the default if not specified.
///
/// Note: The actual authentication behavior can also be influenced by merchant configuration and specific connector defaults. Some connectors might still enforce 3DS or bypass it regardless of this parameter.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::VariantNames,
    strum::EnumIter,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AuthenticationType {
    ThreeDs,
    #[default]
    NoThreeDs,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    Eq,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumString,
    ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EventClass {
    Payments,
    Refunds,
    Disputes,
    Mandates,
}

#[derive(
    Clone,
    Debug,
    Eq,
    Default,
    Hash,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumIter,
    strum::EnumString,
    utoipa::ToSchema,
    Copy,
)]
#[rustfmt::skip]
pub enum CountryAlpha2 {
    AF, AX, AL, DZ, AS, AD, AO, AI, AQ, AG, AR, AM, AW, AU, AT,
    AZ, BS, BH, BD, BB, BY, BE, BZ, BJ, BM, BT, BO, BQ, BA, BW,
    BV, BR, IO, BN, BG, BF, BI, KH, CM, CA, CV, KY, CF, TD, CL,
    CN, CX, CC, CO, KM, CG, CD, CK, CR, CI, HR, CU, CW, CY, CZ,
    DK, DJ, DM, DO, EC, EG, SV, GQ, ER, EE, ET, FK, FO, FJ, FI,
    FR, GF, PF, TF, GA, GM, GE, DE, GH, GI, GR, GL, GD, GP, GU,
    GT, GG, GN, GW, GY, HT, HM, VA, HN, HK, HU, IS, IN, ID, IR,
    IQ, IE, IM, IL, IT, JM, JP, JE, JO, KZ, KE, KI, KP, KR, KW,
    KG, LA, LV, LB, LS, LR, LY, LI, LT, LU, MO, MK, MG, MW, MY,
    MV, ML, MT, MH, MQ, MR, MU, YT, MX, FM, MD, MC, MN, ME, MS,
    MA, MZ, MM, NA, NR, NP, NL, NC, NZ, NI, NE, NG, NU, NF, MP,
    NO, OM, PK, PW, PS, PA, PG, PY, PE, PH, PN, PL, PT, PR, QA,
    RE, RO, RU, RW, BL, SH, KN, LC, MF, PM, VC, WS, SM, ST, SA,
    SN, RS, SC, SL, SG, SX, SK, SI, SB, SO, ZA, GS, SS, ES, LK,
    SD, SR, SJ, SZ, SE, CH, SY, TW, TJ, TZ, TH, TL, TG, TK, TO,
    TT, TN, TR, TM, TC, TV, UG, UA, AE, GB, UM, UY, UZ, VU,
    VE, VN, VG, VI, WF, EH, YE, ZM, ZW,
    #[default]
    US
}
