use std::fmt;
use millegrilles_common_rust::{mongodb, serde_json, uuid};
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::url::ParseError;
use webauthn_rs::prelude::WebauthnError;

#[derive(Debug)]
pub enum Error {
    MillegrillesCryptographie(millegrilles_common_rust::millegrilles_cryptographie::error::Error),
    MillegrillesCommon(millegrilles_common_rust::error::Error),
    Webauthn(WebauthnError),
    UrlParse(millegrilles_common_rust::url::ParseError),
    UuidParse(uuid::Error),
    Multibase(multibase::Error),
    MongDb(mongodb::error::Error),
    SerdeJson(serde_json::Error),
    Str(&'static str),
    String(String)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
}

impl Into<millegrilles_common_rust::error::Error> for Error {
    fn into(self) -> millegrilles_common_rust::error::Error {
        millegrilles_common_rust::error::Error::String(format!("crate::error::Error : {:?}", self))
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<millegrilles_common_rust::millegrilles_cryptographie::error::Error> for Error {
    fn from(value: millegrilles_common_rust::millegrilles_cryptographie::error::Error) -> Self {
        Self::MillegrillesCryptographie(value)
    }
}

impl From<millegrilles_common_rust::error::Error> for Error {
    fn from(value: millegrilles_common_rust::error::Error) -> Self {
        Self::MillegrillesCommon(value)
    }
}

impl From<WebauthnError> for Error {
    fn from(value: WebauthnError) -> Self {
        Self::Webauthn(value)
    }
}

impl From<millegrilles_common_rust::url::ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self::UrlParse(value)
    }
}

impl From<uuid::Error> for Error {
    fn from(value: uuid::Error) -> Self {
        Self::UuidParse(value)
    }
}

impl From<multibase::Error> for Error {
    fn from(value: multibase::Error) -> Self {
        Self::Multibase(value)
    }
}

impl From<mongodb::error::Error> for Error {
    fn from(value: mongodb::error::Error) -> Self {
        Self::MongDb(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self{ Self::SerdeJson(value) }
}
