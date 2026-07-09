// Generated-style Connect-ES client artifact (hand-written fixture).
import { MethodKind } from "@bufbuild/protobuf";
import { GetUserRequest, GetUserResponse, WatchRequest, User, UploadResult, ChatMessage } from "./users_pb.js";

export const UserService = {
  typeName: "users.v1.UserService",
  methods: {
    getUser: {
      name: "GetUser",
      I: GetUserRequest,
      O: GetUserResponse,
      kind: MethodKind.Unary,
    },
    watchUsers: {
      name: "WatchUsers",
      I: WatchRequest,
      O: User,
      kind: MethodKind.ServerStreaming,
    },
    sendUpdates: {
      name: "SendUpdates",
      I: User,
      O: UploadResult,
      kind: MethodKind.ClientStreaming,
    },
    chat: {
      name: "Chat",
      I: ChatMessage,
      O: ChatMessage,
      kind: MethodKind.BiDiStreaming,
    },
  },
};
