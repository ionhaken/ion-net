/*
 * Copyright 2023 Markus Haikonen, Ionhaken
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

namespace ion
{
template <typename T>
class Matrix
{
public:
	Matrix(size_t rows, size_t cols) : mImpl(static_cast<const arma::uword>(rows), static_cast<const arma::uword>(cols)) {}

	Matrix() : mImpl() {}

	void Resize(size_t rows, size_t cols) { mImpl.set_size(rows, cols); }

	T& operator()(size_t row, size_t col) { return mImpl(static_cast<const arma::uword>(row), static_cast<const arma::uword>(col)); }

	T operator()(size_t row, size_t col) const { return mImpl(static_cast<const arma::uword>(row), static_cast<const arma::uword>(col)); }

	size_t GetNumRows() const { return mImpl.n_rows; }

	size_t GetNumCols() const { return mImpl.n_cols; }

private:
	arma::Mat<T> mImpl;
};
}  // namespace ion
