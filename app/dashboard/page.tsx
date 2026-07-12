"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useSession, signOut } from "next-auth/react";
import { io } from "socket.io-client";

export default function Dashboard() {
  const router = useRouter();
  const { data: session, status } = useSession();
  const [onlineUsers, setOnlineUsers] = useState(0);

  useEffect(() => {
    if (status === "unauthenticated") {
      router.push("/login");
    }
  }, [status, router]);

  useEffect(() => {
    const socket = io();

    socket.on("stats", (data: { onlineUsers: number }) => {
      setOnlineUsers(data.onlineUsers);
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  if (status === "loading") {
    return <div style={{ padding: "40px" }}>Loading...</div>;
  }

  if (!session) {
    return null;
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#000",
        color: "#fff",
        padding: "40px",
      }}
    >
      <h1 style={{ fontSize: "32px", marginBottom: "8px" }}>
        ⚡ Real-Time Dashboard
      </h1>

      <p style={{ color: "#9ca3af", marginBottom: "40px" }}>
        Welcome, {session.user?.name || session.user?.email}
        {" — "}
        <button
          onClick={() => signOut({ callbackUrl: "/" })}
          style={{
            background: "none",
            border: "none",
            color: "#60a5fa",
            cursor: "pointer",
            padding: 0,
            fontSize: "inherit",
          }}
        >
          Sign out
        </button>
      </p>

      <div
        style={{
          background: "rgba(255, 255, 255, 0.1)",
          padding: "32px",
          borderRadius: "16px",
          width: "320px",
        }}
      >
        <h2 style={{ fontSize: "20px", marginTop: 0, marginBottom: "8px" }}>
          Online Users
        </h2>
        <p
          style={{
            fontSize: "48px",
            fontWeight: "bold",
            color: "#4ade80",
            margin: 0,
          }}
        >
          {onlineUsers}
        </p>

        <p style={{ fontSize: "13px", color: "#9ca3af", marginTop: "16px" }}>
          Live updates via Socket.io
        </p>
      </div>
    </div>
  );
}
