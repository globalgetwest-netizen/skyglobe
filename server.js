const { createServer } = require("http");
const next = require("next");
const { Server } = require("socket.io");

const dev =
  process.env.NODE_ENV !== "production" &&
  !process.argv.includes("--production");
const port = parseInt(process.env.PORT || "3000", 10);

const app = next({ dev });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const httpServer = createServer((req, res) => handle(req, res));

  const io = new Server(httpServer);

  let onlineUsers = 0;

  io.on("connection", (socket) => {
    onlineUsers++;
    io.emit("stats", { onlineUsers });

    socket.on("disconnect", () => {
      onlineUsers = Math.max(0, onlineUsers - 1);
      io.emit("stats", { onlineUsers });
    });
  });

  httpServer.listen(port, () => {
    console.log(`> Ready on http://localhost:${port}`);
  });
});
