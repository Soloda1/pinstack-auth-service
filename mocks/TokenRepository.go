// Code generated by mockery v2.53.3. DO NOT EDIT.

package mocks

import (
	context "context"
	model "pinstack-auth-service/internal/model"

	mock "github.com/stretchr/testify/mock"

	time "time"
)

// TokenRepository is an autogenerated mock type for the TokenRepository type
type TokenRepository struct {
	mock.Mock
}

type TokenRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *TokenRepository) EXPECT() *TokenRepository_Expecter {
	return &TokenRepository_Expecter{mock: &_m.Mock}
}

// CreateRefreshToken provides a mock function with given fields: ctx, token
func (_m *TokenRepository) CreateRefreshToken(ctx context.Context, token *model.RefreshToken) error {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for CreateRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *model.RefreshToken) error); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenRepository_CreateRefreshToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateRefreshToken'
type TokenRepository_CreateRefreshToken_Call struct {
	*mock.Call
}

// CreateRefreshToken is a helper method to define mock.On call
//   - ctx context.Context
//   - token *model.RefreshToken
func (_e *TokenRepository_Expecter) CreateRefreshToken(ctx interface{}, token interface{}) *TokenRepository_CreateRefreshToken_Call {
	return &TokenRepository_CreateRefreshToken_Call{Call: _e.mock.On("CreateRefreshToken", ctx, token)}
}

func (_c *TokenRepository_CreateRefreshToken_Call) Run(run func(ctx context.Context, token *model.RefreshToken)) *TokenRepository_CreateRefreshToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*model.RefreshToken))
	})
	return _c
}

func (_c *TokenRepository_CreateRefreshToken_Call) Return(_a0 error) *TokenRepository_CreateRefreshToken_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TokenRepository_CreateRefreshToken_Call) RunAndReturn(run func(context.Context, *model.RefreshToken) error) *TokenRepository_CreateRefreshToken_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteExpiredTokens provides a mock function with given fields: ctx, before
func (_m *TokenRepository) DeleteExpiredTokens(ctx context.Context, before time.Time) error {
	ret := _m.Called(ctx, before)

	if len(ret) == 0 {
		panic("no return value specified for DeleteExpiredTokens")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, time.Time) error); ok {
		r0 = rf(ctx, before)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenRepository_DeleteExpiredTokens_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteExpiredTokens'
type TokenRepository_DeleteExpiredTokens_Call struct {
	*mock.Call
}

// DeleteExpiredTokens is a helper method to define mock.On call
//   - ctx context.Context
//   - before time.Time
func (_e *TokenRepository_Expecter) DeleteExpiredTokens(ctx interface{}, before interface{}) *TokenRepository_DeleteExpiredTokens_Call {
	return &TokenRepository_DeleteExpiredTokens_Call{Call: _e.mock.On("DeleteExpiredTokens", ctx, before)}
}

func (_c *TokenRepository_DeleteExpiredTokens_Call) Run(run func(ctx context.Context, before time.Time)) *TokenRepository_DeleteExpiredTokens_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(time.Time))
	})
	return _c
}

func (_c *TokenRepository_DeleteExpiredTokens_Call) Return(_a0 error) *TokenRepository_DeleteExpiredTokens_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TokenRepository_DeleteExpiredTokens_Call) RunAndReturn(run func(context.Context, time.Time) error) *TokenRepository_DeleteExpiredTokens_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteRefreshToken provides a mock function with given fields: ctx, token
func (_m *TokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for DeleteRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenRepository_DeleteRefreshToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteRefreshToken'
type TokenRepository_DeleteRefreshToken_Call struct {
	*mock.Call
}

// DeleteRefreshToken is a helper method to define mock.On call
//   - ctx context.Context
//   - token string
func (_e *TokenRepository_Expecter) DeleteRefreshToken(ctx interface{}, token interface{}) *TokenRepository_DeleteRefreshToken_Call {
	return &TokenRepository_DeleteRefreshToken_Call{Call: _e.mock.On("DeleteRefreshToken", ctx, token)}
}

func (_c *TokenRepository_DeleteRefreshToken_Call) Run(run func(ctx context.Context, token string)) *TokenRepository_DeleteRefreshToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *TokenRepository_DeleteRefreshToken_Call) Return(_a0 error) *TokenRepository_DeleteRefreshToken_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TokenRepository_DeleteRefreshToken_Call) RunAndReturn(run func(context.Context, string) error) *TokenRepository_DeleteRefreshToken_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteRefreshTokenByJTI provides a mock function with given fields: ctx, jti
func (_m *TokenRepository) DeleteRefreshTokenByJTI(ctx context.Context, jti string) error {
	ret := _m.Called(ctx, jti)

	if len(ret) == 0 {
		panic("no return value specified for DeleteRefreshTokenByJTI")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, jti)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenRepository_DeleteRefreshTokenByJTI_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteRefreshTokenByJTI'
type TokenRepository_DeleteRefreshTokenByJTI_Call struct {
	*mock.Call
}

// DeleteRefreshTokenByJTI is a helper method to define mock.On call
//   - ctx context.Context
//   - jti string
func (_e *TokenRepository_Expecter) DeleteRefreshTokenByJTI(ctx interface{}, jti interface{}) *TokenRepository_DeleteRefreshTokenByJTI_Call {
	return &TokenRepository_DeleteRefreshTokenByJTI_Call{Call: _e.mock.On("DeleteRefreshTokenByJTI", ctx, jti)}
}

func (_c *TokenRepository_DeleteRefreshTokenByJTI_Call) Run(run func(ctx context.Context, jti string)) *TokenRepository_DeleteRefreshTokenByJTI_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *TokenRepository_DeleteRefreshTokenByJTI_Call) Return(_a0 error) *TokenRepository_DeleteRefreshTokenByJTI_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TokenRepository_DeleteRefreshTokenByJTI_Call) RunAndReturn(run func(context.Context, string) error) *TokenRepository_DeleteRefreshTokenByJTI_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteUserRefreshTokens provides a mock function with given fields: ctx, userID
func (_m *TokenRepository) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	ret := _m.Called(ctx, userID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUserRefreshTokens")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, int64) error); ok {
		r0 = rf(ctx, userID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TokenRepository_DeleteUserRefreshTokens_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteUserRefreshTokens'
type TokenRepository_DeleteUserRefreshTokens_Call struct {
	*mock.Call
}

// DeleteUserRefreshTokens is a helper method to define mock.On call
//   - ctx context.Context
//   - userID int64
func (_e *TokenRepository_Expecter) DeleteUserRefreshTokens(ctx interface{}, userID interface{}) *TokenRepository_DeleteUserRefreshTokens_Call {
	return &TokenRepository_DeleteUserRefreshTokens_Call{Call: _e.mock.On("DeleteUserRefreshTokens", ctx, userID)}
}

func (_c *TokenRepository_DeleteUserRefreshTokens_Call) Run(run func(ctx context.Context, userID int64)) *TokenRepository_DeleteUserRefreshTokens_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(int64))
	})
	return _c
}

func (_c *TokenRepository_DeleteUserRefreshTokens_Call) Return(_a0 error) *TokenRepository_DeleteUserRefreshTokens_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TokenRepository_DeleteUserRefreshTokens_Call) RunAndReturn(run func(context.Context, int64) error) *TokenRepository_DeleteUserRefreshTokens_Call {
	_c.Call.Return(run)
	return _c
}

// GetRefreshToken provides a mock function with given fields: ctx, token
func (_m *TokenRepository) GetRefreshToken(ctx context.Context, token string) (*model.RefreshToken, error) {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for GetRefreshToken")
	}

	var r0 *model.RefreshToken
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*model.RefreshToken, error)); ok {
		return rf(ctx, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *model.RefreshToken); ok {
		r0 = rf(ctx, token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.RefreshToken)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TokenRepository_GetRefreshToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRefreshToken'
type TokenRepository_GetRefreshToken_Call struct {
	*mock.Call
}

// GetRefreshToken is a helper method to define mock.On call
//   - ctx context.Context
//   - token string
func (_e *TokenRepository_Expecter) GetRefreshToken(ctx interface{}, token interface{}) *TokenRepository_GetRefreshToken_Call {
	return &TokenRepository_GetRefreshToken_Call{Call: _e.mock.On("GetRefreshToken", ctx, token)}
}

func (_c *TokenRepository_GetRefreshToken_Call) Run(run func(ctx context.Context, token string)) *TokenRepository_GetRefreshToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *TokenRepository_GetRefreshToken_Call) Return(_a0 *model.RefreshToken, _a1 error) *TokenRepository_GetRefreshToken_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *TokenRepository_GetRefreshToken_Call) RunAndReturn(run func(context.Context, string) (*model.RefreshToken, error)) *TokenRepository_GetRefreshToken_Call {
	_c.Call.Return(run)
	return _c
}

// GetRefreshTokenByJTI provides a mock function with given fields: ctx, jti
func (_m *TokenRepository) GetRefreshTokenByJTI(ctx context.Context, jti string) (*model.RefreshToken, error) {
	ret := _m.Called(ctx, jti)

	if len(ret) == 0 {
		panic("no return value specified for GetRefreshTokenByJTI")
	}

	var r0 *model.RefreshToken
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*model.RefreshToken, error)); ok {
		return rf(ctx, jti)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *model.RefreshToken); ok {
		r0 = rf(ctx, jti)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.RefreshToken)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, jti)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TokenRepository_GetRefreshTokenByJTI_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRefreshTokenByJTI'
type TokenRepository_GetRefreshTokenByJTI_Call struct {
	*mock.Call
}

// GetRefreshTokenByJTI is a helper method to define mock.On call
//   - ctx context.Context
//   - jti string
func (_e *TokenRepository_Expecter) GetRefreshTokenByJTI(ctx interface{}, jti interface{}) *TokenRepository_GetRefreshTokenByJTI_Call {
	return &TokenRepository_GetRefreshTokenByJTI_Call{Call: _e.mock.On("GetRefreshTokenByJTI", ctx, jti)}
}

func (_c *TokenRepository_GetRefreshTokenByJTI_Call) Run(run func(ctx context.Context, jti string)) *TokenRepository_GetRefreshTokenByJTI_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *TokenRepository_GetRefreshTokenByJTI_Call) Return(_a0 *model.RefreshToken, _a1 error) *TokenRepository_GetRefreshTokenByJTI_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *TokenRepository_GetRefreshTokenByJTI_Call) RunAndReturn(run func(context.Context, string) (*model.RefreshToken, error)) *TokenRepository_GetRefreshTokenByJTI_Call {
	_c.Call.Return(run)
	return _c
}

// NewTokenRepository creates a new instance of TokenRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTokenRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *TokenRepository {
	mock := &TokenRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
