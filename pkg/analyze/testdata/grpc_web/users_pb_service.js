// Generated-style grpc-web service stub (*_pb_service.js) — hand-written fixture.
var users_pb = require("./users_pb.js");
var UserService = (function () {
  function UserService() {}
  UserService.serviceName = "users.v1.UserService";
  return UserService;
})();

UserService.GetUser = {
  methodName: "GetUser",
  service: UserService,
  requestStream: false,
  responseStream: false,
  requestType: users_pb.GetUserRequest,
  responseType: users_pb.GetUserResponse,
};

UserService.UploadUsers = {
  methodName: "UploadUsers",
  service: UserService,
  requestStream: true,
  responseStream: false,
  requestType: users_pb.UploadUsersRequest,
  responseType: users_pb.UploadUsersResponse,
};

module.exports = UserService;
