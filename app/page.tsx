import Link from "next/link";

export default function Home() {
  return (
    <div style={{ padding: "40px" }}>
      <h1>Skyglobe</h1>
      <p>Your Gateway to Travel & Study Abroad</p>

      <p>
        <Link href="/login">Login</Link>
        {" | "}
        <Link href="/register">Register</Link>
        {" | "}
        <Link href="/dashboard">Dashboard</Link>
      </p>
    </div>
  );
}
