use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A two-dimensional extent in logical or physical pixels.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    pub const fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// A signed point in logical or physical pixels.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// A rectangle represented by an origin and extent.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Rect {
    pub origin: Point,
    pub size: Size,
}

impl Rect {
    pub const fn new(origin: Point, size: Size) -> Self {
        Self { origin, size }
    }
}

/// A positive, normalized ratio of physical pixels to logical pixels.
///
/// Both components are non-zero and always reduced to lowest terms. For
/// example, `ScaleFactor::new(6, 4)` produces the same value as `3/2`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScaleFactor {
    numerator: u32,
    denominator: u32,
}

impl ScaleFactor {
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    pub const fn new(numerator: u32, denominator: u32) -> Result<Self, ScaleFactorError> {
        if numerator == 0 {
            return Err(ScaleFactorError::ZeroNumerator);
        }
        if denominator == 0 {
            return Err(ScaleFactorError::ZeroDenominator);
        }
        let divisor = greatest_common_divisor(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    pub const fn numerator(self) -> u32 {
        self.numerator
    }

    pub const fn denominator(self) -> u32 {
        self.denominator
    }

    /// Scales a logical extent to physical pixels, rounding each dimension up.
    pub fn scale_size(self, logical_size: Size) -> Option<Size> {
        Some(Size::new(
            scale_dimension(logical_size.width, self)?,
            scale_dimension(logical_size.height, self)?,
        ))
    }
}

impl Default for ScaleFactor {
    fn default() -> Self {
        Self::ONE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScaleFactorError {
    ZeroNumerator,
    ZeroDenominator,
}

#[derive(Deserialize, Serialize)]
struct ScaleFactorWire {
    numerator: u32,
    denominator: u32,
}

impl Serialize for ScaleFactor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ScaleFactorWire {
            numerator: self.numerator,
            denominator: self.denominator,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScaleFactor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ScaleFactorWire::deserialize(deserializer)?;
        Self::new(wire.numerator, wire.denominator)
            .map_err(|_| serde::de::Error::custom("scale factor components must be non-zero"))
    }
}

const fn greatest_common_divisor(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn scale_dimension(logical: u32, scale: ScaleFactor) -> Option<u32> {
    let scaled = u64::from(logical)
        .checked_mul(u64::from(scale.numerator))?
        .checked_add(u64::from(scale.denominator - 1))?
        / u64::from(scale.denominator);
    u32::try_from(scaled).ok()
}
