extern crate yaml_rust;
extern crate rustc_serialize;

use std::fs::File;
use std::io::{self, Read};
use std::ops::Deref;
use std::ascii::AsciiExt;
use std::fmt;

use rustc_serialize::{Decodable, Decoder};
use yaml_rust::{yaml, Yaml, YamlLoader, ScanError};

#[derive(Debug)]
pub enum ParseError {
    Read(io::Error),
    Syntax(ScanError),
    NoDocument,
    InvalidType(&'static str, Yaml),
    InvalidOption(String, Vec<String>),
    Unsupported(&'static str),
    Other(String)
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ParseError::Read(ref err) => write!(formatter, "Failed to read config: {}", err),
            ParseError::Syntax(ref err) => write!(formatter, "Invalid config syntax: {}", err),
            ParseError::NoDocument => write!(formatter, "Config was empty"),
            ParseError::InvalidType(ref exp, ref value) => write!(formatter, "Invalid value encountered for type {}: {:?}", exp, value),
            ParseError::InvalidOption(ref opt, ref opts) => write!(formatter, "Invalid option value {}, choices were {:?}", opt, opts),
            ParseError::Unsupported(ref reason) => write!(formatter, "Failed to decode config: {}", reason),
            ParseError::Other(ref reason) => write!(formatter, "Failed to decode config: {}", reason)
        }
    }
}


pub fn parse<T: Decodable>(file: &str) -> Result<T, ParseError> {
    let mut file = try!(File::open(file).map_err(ParseError::Read));
    let mut text = String::new();
    try!(file.read_to_string(&mut text).map_err(ParseError::Read));
    parse_str(&text)
}

pub fn parse_str<T: Decodable>(text: &str) -> Result<T, ParseError> {
    if let Some(yaml) = try!(YamlLoader::load_from_str(text).map_err(ParseError::Syntax)).pop() {
        parse_yaml(yaml)
    } else {
        Err(ParseError::NoDocument)
    }
}

pub fn parse_yaml<T: Decodable>(yaml: Yaml) -> Result<T, ParseError> {
    T::decode(&mut YamlDecoder(yaml))
}

struct YamlDecoder(Yaml);

static NULL: Yaml = Yaml::Null;

impl YamlDecoder {
    #[inline]
    fn get_field(&self, name: &str) -> Result<Yaml, ParseError> {
        match self.as_hash() {
            Some(hash) => match hash.get(&Yaml::String(name.to_string())) {
                Some(field) => Ok(field.clone()),
                None => Ok(Yaml::Null)
            },
            None => Err(ParseError::InvalidType("hash", self.0.clone()))
        }
    }

    #[inline]
    fn get_item(&self, index: usize) -> Result<&Yaml, ParseError> {
        match self.as_vec() {
            Some(vec) => if vec.len() > index {
                Ok(&vec[index])
            } else {
                Ok(&NULL)
            },
            None => Err(ParseError::InvalidType("hash", self.0.clone()))
        }
    }

    #[inline]
    fn vec(&self) -> Result<&yaml::Array, ParseError> {
        match self.as_vec() {
            Some(vec) => Ok(vec),
            None => Err(ParseError::InvalidType("list", self.0.clone()))
        }
    }

    #[inline]
    fn hash(&self) -> Result<&yaml::Hash, ParseError> {
        match self.as_hash() {
            Some(hash) => Ok(hash),
            None => Err(ParseError::InvalidType("hash", self.0.clone()))
        }
    }

    #[inline]
    fn bool(&self) -> Result<bool, ParseError> {
        self.0.as_bool().ok_or_else(|| ParseError::InvalidType("bool", self.0.clone()))
    }

    #[inline]
    fn num(&self) -> Result<i64, ParseError> {
        self.0.as_i64().ok_or_else(|| ParseError::InvalidType("number", self.0.clone()))
    }

    #[inline]
    fn float(&self) -> Result<f64, ParseError> {
        self.0.as_f64().ok_or_else(|| ParseError::InvalidType("float", self.0.clone()))
    }

    #[inline]
    fn str(&self) -> Result<&str, ParseError> {
        self.as_str().ok_or_else(|| ParseError::InvalidType("string", self.0.clone()))
    }
}

impl Deref for YamlDecoder {
    type Target = Yaml;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Decoder for YamlDecoder {
    type Error = ParseError;

    #[inline]
    fn read_nil(&mut self) -> Result<(), ParseError> {
        Ok(())
    }

    #[inline]
    fn read_bool(&mut self) -> Result<bool, ParseError> {
        self.bool()
    }

    #[inline]
    fn read_f64(&mut self) -> Result<f64, ParseError> {
        self.float()
    }

    #[inline]
    fn read_f32(&mut self) -> Result<f32, ParseError> {
        Ok(try!(self.float()) as f32)
    }

    #[inline]
    fn read_i64(&mut self) -> Result<i64, ParseError> {
        self.num()
    }

    #[inline]
    fn read_i32(&mut self) -> Result<i32, ParseError> {
        Ok(try!(self.num()) as i32)
    }

    #[inline]
    fn read_i16(&mut self) -> Result<i16, ParseError> {
        Ok(try!(self.num()) as i16)
    }

    #[inline]
    fn read_i8(&mut self) -> Result<i8, ParseError> {
        Ok(try!(self.num()) as i8)
    }

    #[inline]
    fn read_isize(&mut self) -> Result<isize, ParseError> {
        Ok(try!(self.num()) as isize)
    }

    #[inline]
    fn read_u64(&mut self) -> Result<u64, ParseError> {
        Ok(try!(self.num()) as u64)
    }

    #[inline]
    fn read_u32(&mut self) -> Result<u32, ParseError> {
        Ok(try!(self.read_u64()) as u32)
    }

    #[inline]
    fn read_u16(&mut self) -> Result<u16, ParseError> {
        Ok(try!(self.read_u64()) as u16)
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, ParseError> {
        Ok(try!(self.read_u64()) as u8)
    }

    #[inline]
    fn read_usize(&mut self) -> Result<usize, ParseError> {
        Ok(try!(self.read_u64()) as usize)
    }

    #[inline]
    fn read_str(&mut self) -> Result<String, ParseError> {
        self.str().map(|val| val.to_string())
    }

    #[inline]
    fn read_char(&mut self) -> Result<char, ParseError> {
        let string = try!(self.str());
        if string.len() == 1 {
            Ok(string.chars().next().unwrap())
        } else {
            Err(ParseError::InvalidType("char", self.clone()))
        }
    }

    fn read_enum<T, F>(&mut self, _name: &str, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(self)
    }

    fn read_enum_variant<T, F>(&mut self, names: &[&str], mut f: F) -> Result<T, Self::Error> where F: FnMut(&mut Self, usize) -> Result<T, Self::Error> {
        let name = try!(self.read_str());
        for (i, n) in names.iter().enumerate() {
            if n == &name {
                return f(self, i)
            }
        }
        for (i, n) in names.iter().enumerate() {
            if n.eq_ignore_ascii_case(&name) {
                return f(self, i)
            }
        }
        Err(ParseError::InvalidOption(name, names.iter().map(|s| s.to_string()).collect()))
    }

    fn read_enum_variant_arg<T, F>(&mut self, _a_idx: usize, _f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        Err(ParseError::Unsupported("Enum variants with aruments are not supported"))
    }

    fn read_enum_struct_variant<T, F>(&mut self, _names: &[&str], _f: F) -> Result<T, Self::Error> where F: FnMut(&mut Self, usize) -> Result<T, Self::Error> {
        Err(ParseError::Unsupported("Enum variants with aruments are not supported"))
    }

    fn read_enum_struct_variant_field<T, F>(&mut self, _f_name: &str, _f_idx: usize, _f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        Err(ParseError::Unsupported("Enum variants with aruments are not supported"))
    }

    fn read_struct<T, F>(&mut self, _s_name: &str, _len: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(self)
    }

    fn read_struct_field<T, F>(&mut self, f_name: &str, _f_idx: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(&mut YamlDecoder(try!(self.get_field(f_name))))
    }

    fn read_tuple<T, F>(&mut self, _len: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(self)
    }

    fn read_tuple_arg<T, F>(&mut self, a_idx: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(&mut YamlDecoder(try!(self.get_item(a_idx)).clone()))
    }

    fn read_tuple_struct<T, F>(&mut self, _s_name: &str, _len: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(self)
    }

    fn read_tuple_struct_arg<T, F>(&mut self, a_idx: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(&mut YamlDecoder(try!(self.get_item(a_idx)).clone()))
    }

    fn read_option<T, F>(&mut self, mut f: F) -> Result<T, Self::Error> where F: FnMut(&mut Self, bool) -> Result<T, Self::Error> {
        let isset = !self.is_null();
        f(self, isset)
    }

    fn read_seq<T, F>(&mut self, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self, usize) -> Result<T, Self::Error> {
        let len = try!(self.vec()).len();
        f(self, len)
    }

    fn read_seq_elt<T, F>(&mut self, idx: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(&mut YamlDecoder(try!(self.vec())[idx].clone()))
    }

    fn read_map<T, F>(&mut self, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self, usize) -> Result<T, Self::Error> {
        let len = try!(self.hash()).len();
        f(self, len)
    }

    fn read_map_elt_key<T, F>(&mut self, idx: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(&mut YamlDecoder(try!(self.hash()).into_iter().nth(idx).unwrap().0.clone()))
    }

    fn read_map_elt_val<T, F>(&mut self, idx: usize, f: F) -> Result<T, Self::Error> where F: FnOnce(&mut Self) -> Result<T, Self::Error> {
        f(&mut YamlDecoder(try!(self.hash()).into_iter().nth(idx).unwrap().1.clone()))
    }

    fn error(&mut self, err: &str) -> Self::Error {
        ParseError::Other(err.to_string())
    }

}
