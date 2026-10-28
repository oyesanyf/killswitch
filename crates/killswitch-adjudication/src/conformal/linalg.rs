use std::ops::{DivAssign, Index, IndexMut, Sub};

/// 1D numerical vector type compatible with standard linear algebra interfaces.
#[derive(Clone, Debug, PartialEq)]
pub struct Array1<T> {
    data: Vec<T>,
}

impl<T> Array1<T> {
    pub fn from_vec(data: Vec<T>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }
}

impl Array1<f64> {
    pub fn zeros(len: usize) -> Self {
        Self {
            data: vec![0.0; len],
        }
    }

    pub fn dot(&self, other: &Self) -> f64 {
        assert_eq!(self.len(), other.len(), "Dimension mismatch in dot product");
        self.data
            .iter()
            .zip(other.data.iter())
            .map(|(&a, &b)| a * b)
            .sum()
    }
}

impl<T> Index<usize> for Array1<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl<T> IndexMut<usize> for Array1<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl<'b> Sub<&'b Array1<f64>> for &Array1<f64> {
    type Output = Array1<f64>;
    fn sub(self, rhs: &'b Array1<f64>) -> Self::Output {
        assert_eq!(self.len(), rhs.len(), "Dimension mismatch in subtraction");
        let data = self
            .data
            .iter()
            .zip(rhs.data.iter())
            .map(|(&a, &b)| a - b)
            .collect();
        Array1 { data }
    }
}

impl<'b> Sub<&'b Array1<f64>> for Array1<f64> {
    type Output = Array1<f64>;
    fn sub(self, rhs: &'b Array1<f64>) -> Self::Output {
        &self - rhs
    }
}

impl Sub<Array1<f64>> for Array1<f64> {
    type Output = Array1<f64>;
    fn sub(self, rhs: Array1<f64>) -> Self::Output {
        &self - &rhs
    }
}

impl DivAssign<f64> for Array1<f64> {
    fn div_assign(&mut self, rhs: f64) {
        for v in &mut self.data {
            *v /= rhs;
        }
    }
}

/// 2D numerical matrix type compatible with standard linear algebra interfaces.
#[derive(Clone, Debug, PartialEq)]
pub struct Array2<T> {
    data: Vec<T>,
    rows: usize,
    cols: usize,
}

impl<T> Array2<T> {
    pub fn shape(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }
}

impl Array2<f64> {
    pub fn zeros(shape: (usize, usize)) -> Self {
        Self {
            data: vec![0.0; shape.0 * shape.1],
            rows: shape.0,
            cols: shape.1,
        }
    }

    pub fn eye(dim: usize) -> Self {
        let mut mat = Self::zeros((dim, dim));
        for i in 0..dim {
            mat[[i, i]] = 1.0;
        }
        mat
    }

    /// Matrix-vector multiplication: y = A * x
    pub fn dot(&self, vec: &Array1<f64>) -> Array1<f64> {
        assert_eq!(self.cols, vec.len(), "Matrix cols must match vector len");
        let mut out = Vec::with_capacity(self.rows);
        for r in 0..self.rows {
            let row_start = r * self.cols;
            let sum: f64 = (0..self.cols)
                .map(|c| self.data[row_start + c] * vec[c])
                .sum();
            out.push(sum);
        }
        Array1::from_vec(out)
    }
}

impl<T> Index<[usize; 2]> for Array2<T> {
    type Output = T;
    fn index(&self, index: [usize; 2]) -> &Self::Output {
        let (r, c) = (index[0], index[1]);
        assert!(r < self.rows && c < self.cols, "Matrix index out of bounds");
        &self.data[r * self.cols + c]
    }
}

impl<T> IndexMut<[usize; 2]> for Array2<T> {
    fn index_mut(&mut self, index: [usize; 2]) -> &mut Self::Output {
        let (r, c) = (index[0], index[1]);
        assert!(r < self.rows && c < self.cols, "Matrix index out of bounds");
        &mut self.data[r * self.cols + c]
    }
}

/// Helper macro to construct an Array1 from an expression list.
#[macro_export]
macro_rules! array {
    ($($x:expr),* $(,)?) => {
        $crate::conformal::linalg::Array1::from_vec(vec![$($x as f64),*])
    };
}
