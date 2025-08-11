package auth_grpc_test

import (
	"context"
	"github.com/soloda1/pinstack-proto-definitions/custom_errors"
	auth_grpc "pinstack-auth-service/internal/delivery/grpc/auth"
	"testing"

	"pinstack-auth-service/internal/auth"
	"pinstack-auth-service/internal/logger"
	"pinstack-auth-service/mocks"

	pb "github.com/soloda1/pinstack-proto-definitions/gen/go/pinstack-proto-definitions/auth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func setupTest(t *testing.T) (*auth_grpc.AuthGRPCService, *mocks.TokenService, func()) {
	mockTokenService := mocks.NewTokenService(t)
	log := logger.New("test")
	service := auth_grpc.NewAuthGRPCService(mockTokenService, log)
	return service, mockTokenService, func() {}
}

func TestAuthGRPCService_Login(t *testing.T) {
	service, mockTokenService, cleanup := setupTest(t)
	defer cleanup()

	t.Run("successful login", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		tokens := &auth.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token"}
		mockTokenService.On("Login", mock.Anything, "test@example.com", "password123").Return(tokens, nil)

		req := &pb.LoginRequest{Login: "test@example.com", Password: "password123"}
		resp, err := service.Login(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, tokens.AccessToken, resp.AccessToken)
		assert.Equal(t, tokens.RefreshToken, resp.RefreshToken)
	})

	t.Run("user not found", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Login", mock.Anything, "notfound@example.com", "password123").Return(nil, custom_errors.ErrUserNotFound)

		req := &pb.LoginRequest{Login: "notfound@example.com", Password: "password123"}
		resp, err := service.Login(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("invalid password", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Login", mock.Anything, "test@example.com", "wrongpassword").Return(nil, custom_errors.ErrInvalidPassword)

		req := &pb.LoginRequest{Login: "test@example.com", Password: "wrongpassword"}
		resp, err := service.Login(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("internal service error", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Login", mock.Anything, "test@example.com", "password123").Return(nil, custom_errors.ErrInternalServiceError)

		req := &pb.LoginRequest{Login: "test@example.com", Password: "password123"}
		resp, err := service.Login(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Nil(t, resp)
	})
}

func TestAuthGRPCService_Register(t *testing.T) {
	service, mockTokenService, cleanup := setupTest(t)
	defer cleanup()

	t.Run("successful registration", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		tokens := &auth.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token"}
		mockTokenService.On("Register", mock.Anything, mock.AnythingOfType("*model.User")).Return(tokens, nil)

		req := &pb.RegisterRequest{Username: "testuser", Email: "test@example.com", Password: "password123"}
		resp, err := service.Register(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, tokens.AccessToken, resp.AccessToken)
		assert.Equal(t, tokens.RefreshToken, resp.RefreshToken)
	})

	t.Run("username already exists", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Register", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil, custom_errors.ErrUsernameExists)

		req := &pb.RegisterRequest{Username: "testuser", Email: "test@example.com", Password: "password123"}
		resp, err := service.Register(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.AlreadyExists, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("email already exists", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Register", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil, custom_errors.ErrEmailExists)

		req := &pb.RegisterRequest{Username: "testuser", Email: "test@example.com", Password: "password123"}
		resp, err := service.Register(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.AlreadyExists, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("invalid input data", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		req := &pb.RegisterRequest{Username: "te", Email: "invalid-email", Password: "short"}
		resp, err := service.Register(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("internal service error", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Register", mock.Anything, mock.AnythingOfType("*model.User")).Return(nil, custom_errors.ErrInternalServiceError)

		req := &pb.RegisterRequest{Username: "testuser", Email: "test@example.com", Password: "password123"}
		resp, err := service.Register(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Nil(t, resp)
	})
}

func TestAuthGRPCService_Refresh(t *testing.T) {
	service, mockTokenService, cleanup := setupTest(t)
	defer cleanup()

	t.Run("successful token refresh", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		tokens := &auth.TokenPair{AccessToken: "new-access-token", RefreshToken: "new-refresh-token"}
		mockTokenService.On("Refresh", mock.Anything, "valid-refresh-token").Return(tokens, nil)

		req := &pb.RefreshRequest{RefreshToken: "valid-refresh-token"}
		resp, err := service.Refresh(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, tokens.AccessToken, resp.AccessToken)
		assert.Equal(t, tokens.RefreshToken, resp.RefreshToken)
	})

	t.Run("expired token", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Refresh", mock.Anything, "expired-refresh-token").Return(nil, custom_errors.ErrTokenExpired)

		req := &pb.RefreshRequest{RefreshToken: "expired-refresh-token"}
		resp, err := service.Refresh(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("invalid token", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Refresh", mock.Anything, "invalid-refresh-token").Return(nil, custom_errors.ErrInvalidToken)

		req := &pb.RefreshRequest{RefreshToken: "invalid-refresh-token"}
		resp, err := service.Refresh(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("user not found", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Refresh", mock.Anything, "valid-refresh-token").Return(nil, custom_errors.ErrUserNotFound)

		req := &pb.RefreshRequest{RefreshToken: "valid-refresh-token"}
		resp, err := service.Refresh(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("operation not allowed", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Refresh", mock.Anything, "valid-refresh-token").Return(nil, custom_errors.ErrOperationNotAllowed)

		req := &pb.RefreshRequest{RefreshToken: "valid-refresh-token"}
		resp, err := service.Refresh(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("internal service error", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Refresh", mock.Anything, "valid-refresh-token").Return(nil, custom_errors.ErrInternalServiceError)

		req := &pb.RefreshRequest{RefreshToken: "valid-refresh-token"}
		resp, err := service.Refresh(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Nil(t, resp)
	})
}

func TestAuthGRPCService_Logout(t *testing.T) {
	service, mockTokenService, cleanup := setupTest(t)
	defer cleanup()

	t.Run("successful logout", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Logout", mock.Anything, "valid-refresh-token").Return(nil)

		req := &pb.LogoutRequest{RefreshToken: "valid-refresh-token"}
		resp, err := service.Logout(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.IsType(t, &emptypb.Empty{}, resp)
	})

	t.Run("invalid token", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Logout", mock.Anything, "invalid-refresh-token").Return(custom_errors.ErrInvalidToken)

		req := &pb.LogoutRequest{RefreshToken: "invalid-refresh-token"}
		resp, err := service.Logout(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("internal service error", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("Logout", mock.Anything, "valid-refresh-token").Return(custom_errors.ErrInternalServiceError)

		req := &pb.LogoutRequest{RefreshToken: "valid-refresh-token"}
		resp, err := service.Logout(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Nil(t, resp)
	})
}

func TestAuthGRPCService_UpdatePassword(t *testing.T) {
	service, mockTokenService, cleanup := setupTest(t)
	defer cleanup()

	t.Run("successful password update", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("UpdatePassword", mock.Anything, int64(1), "oldpassword123", "newpassword123").Return(nil)

		req := &pb.UpdatePasswordRequest{Id: 1, OldPassword: "oldpassword123", NewPassword: "newpassword123"}
		resp, err := service.UpdatePassword(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.IsType(t, &emptypb.Empty{}, resp)
	})

	t.Run("password too short", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		req := &pb.UpdatePasswordRequest{Id: 1, OldPassword: "oldpassword123", NewPassword: "short"}
		resp, err := service.UpdatePassword(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("user not found", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("UpdatePassword", mock.Anything, int64(999), "oldpassword123", "newpassword123").Return(custom_errors.ErrUserNotFound)

		req := &pb.UpdatePasswordRequest{Id: 999, OldPassword: "oldpassword123", NewPassword: "newpassword123"}
		resp, err := service.UpdatePassword(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("invalid old password", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("UpdatePassword", mock.Anything, int64(1), "wrongpassword", "newpassword123").Return(custom_errors.ErrInvalidPassword)

		req := &pb.UpdatePasswordRequest{Id: 1, OldPassword: "wrongpassword", NewPassword: "newpassword123"}
		resp, err := service.UpdatePassword(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("external service error", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("UpdatePassword", mock.Anything, int64(1), "oldpassword123", "newpassword123").Return(custom_errors.ErrExternalServiceError)

		req := &pb.UpdatePasswordRequest{Id: 1, OldPassword: "oldpassword123", NewPassword: "newpassword123"}
		resp, err := service.UpdatePassword(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Nil(t, resp)
	})

	t.Run("internal service error", func(t *testing.T) {
		mockTokenService.ExpectedCalls = nil
		mockTokenService.Calls = nil

		mockTokenService.On("UpdatePassword", mock.Anything, int64(1), "oldpassword123", "newpassword123").Return(custom_errors.ErrInternalServiceError)

		req := &pb.UpdatePasswordRequest{Id: 1, OldPassword: "oldpassword123", NewPassword: "newpassword123"}
		resp, err := service.UpdatePassword(context.Background(), req)
		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Nil(t, resp)
	})
}
