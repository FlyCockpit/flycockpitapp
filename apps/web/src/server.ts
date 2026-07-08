import handler from "@tanstack/react-start/server-entry";

export default {
  fetch(request: Request): Response | Promise<Response> {
    return handler.fetch(request);
  },
};
