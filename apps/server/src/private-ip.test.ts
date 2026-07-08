import { describe, expect, it } from "vitest";
import { isPrivateIp } from "./private-ip.js";

describe("isPrivateIp (IPv4)", () => {
  it.each([
    "0.0.0.0",
    "10.1.2.3",
    "127.0.0.1",
    "100.64.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "192.0.0.1",
    "198.18.0.1",
    "224.0.0.1",
  ])("treats %s as private", (ip) => {
    expect(isPrivateIp(ip, 4)).toBe(true);
  });

  it.each([
    "8.8.8.8",
    "1.1.1.1",
    "203.0.113.10",
    "198.51.100.7",
    "172.32.0.1",
  ])("treats %s as public", (ip) => {
    expect(isPrivateIp(ip, 4)).toBe(false);
  });

  it("fails closed on malformed input", () => {
    expect(isPrivateIp("not-an-ip", 4)).toBe(true);
    expect(isPrivateIp("999.1.1.1", 4)).toBe(true);
  });
});

describe("isPrivateIp (IPv6)", () => {
  it.each(["::", "::1", "fc00::1", "fd12:3456::1"])("treats %s as private", (ip) => {
    expect(isPrivateIp(ip, 6)).toBe(true);
  });

  it.each([
    "fe80::1",
    "fe90::1",
    "fea0::1",
    "feb0::1",
    "febf::1",
  ])("treats the full fe80::/10 link-local range (%s) as private", (ip) => {
    expect(isPrivateIp(ip, 6)).toBe(true);
  });

  it("strips a zone id before classifying", () => {
    expect(isPrivateIp("fe80::1%eth0", 6)).toBe(true);
  });

  it.each([
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:192.168.1.1",
    "::ffff:172.16.0.1",
    "::ffff:169.254.169.254",
    "::ffff:100.64.0.1",
    "::ffff:198.18.0.1",
  ])("unwraps IPv4-mapped %s and blocks it", (ip) => {
    expect(isPrivateIp(ip, 6)).toBe(true);
  });

  it("unwraps the all-hex IPv4-mapped form (::ffff:a9fe:a9fe = 169.254.169.254)", () => {
    expect(isPrivateIp("::ffff:a9fe:a9fe", 6)).toBe(true);
    // ::ffff:ac10:0001 = 172.16.0.1
    expect(isPrivateIp("::ffff:ac10:0001", 6)).toBe(true);
  });

  it.each([
    "2001:db8::5",
    "2606:4700::1111",
    "::ffff:8.8.8.8",
    "::ffff:0808:0808",
  ])("treats public address %s as public", (ip) => {
    expect(isPrivateIp(ip, 6)).toBe(false);
  });
});

describe("isPrivateIp (unknown family)", () => {
  it("fails closed", () => {
    expect(isPrivateIp("8.8.8.8", 0)).toBe(true);
  });
});
