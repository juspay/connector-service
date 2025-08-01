pub mod adyen;
pub use self::adyen::Adyen;

pub mod razorpay;
pub use self::razorpay::Razorpay;

pub mod authorizedotnet;
pub use self::authorizedotnet::Authorizedotnet;
pub mod fiserv;
pub use self::fiserv::Fiserv;
pub mod razorpayv2;
pub use self::razorpayv2::RazorpayV2;

// pub use self::{
//     adyen::Adyen
//     // authorizedotnet::Authorizedotnet, fiserv::Fiserv, razorpay::Razorpay,
//     // razorpayv2::RazorpayV2,
// };

pub mod elavon;
pub use self::elavon::Elavon;

pub mod xendit;
pub use self::xendit::Xendit;

pub mod macros;

pub mod checkout;
pub use self::checkout::Checkout;
