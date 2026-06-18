// Generated-style grpc-web MethodDescriptor artifact (*_grpc_web_pb.js) — fixture.
const grpc = {};
grpc.web = require("grpc-web");

const proto = {};
proto.users = {};
proto.users.v1 = require("./users_pb.js");

const methodDescriptor_UserService_GetUser = new grpc.web.MethodDescriptor(
  "/users.v1.UserService/GetUser",
  grpc.web.MethodType.UNARY,
  proto.users.v1.GetUserRequest,
  proto.users.v1.GetUserResponse,
  function (request) {
    return request.serializeBinary();
  },
  proto.users.v1.GetUserResponse.deserializeBinary
);

const methodDescriptor_UserService_WatchUsers = new grpc.web.MethodDescriptor(
  "/users.v1.UserService/WatchUsers",
  grpc.web.MethodType.SERVER_STREAMING,
  proto.users.v1.WatchRequest,
  proto.users.v1.User,
  function (request) {
    return request.serializeBinary();
  },
  proto.users.v1.User.deserializeBinary
);
