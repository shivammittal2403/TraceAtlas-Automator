"use strict";

(function exposeTargetValidation(root) {
  function parseIPv4(value) {
    if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) return null;
    const octets = value.split(".").map(Number);
    return octets.every((part) => part <= 255) ? octets : null;
  }

  function isPublicIPv4(value) {
    const octets = parseIPv4(value);
    if (!octets) return false;
    const [a, b, c] = octets;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && (b === 0 && c === 0 || b === 168 || b === 88 && c === 99)) return false;
    if (a === 192 && b === 0 && c === 2) return false;
    if (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }

  function parseIPv6(value) {
    if (!/^[0-9a-f:]+$/i.test(value) || !value.includes(":")) return null;
    const halves = value.split("::");
    if (halves.length > 2) return null;
    const parseHalf = (half) => {
      if (!half) return [];
      const groups = half.split(":");
      if (groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return null;
      return groups.map((group) => Number.parseInt(group, 16));
    };
    const left = parseHalf(halves[0]);
    const right = parseHalf(halves.length === 2 ? halves[1] : "");
    if (!left || !right) return null;
    if (halves.length === 1) return left.length === 8 ? left : null;
    const zeroCount = 8 - left.length - right.length;
    if (zeroCount < 1) return null;
    return [...left, ...Array(zeroCount).fill(0), ...right];
  }

  function isPublicIPv6(value) {
    const groups = parseIPv6(value);
    if (!groups) return false;
    const [first, second] = groups;
    // Accept global-unicast space only; exclude IETF protocol assignments,
    // documentation space, and 6to4 because their reachability is not general.
    if ((first & 0xe000) !== 0x2000) return false;
    if (first === 0x2001 && (
      second <= 1 || second === 0x0db8 || second === 0x0010 || second === 0x0020 ||
      second === 2 && groups[2] === 0
    )) return false;
    if (first === 0x2002) return false;
    if (first === 0x3fff && second <= 0x0fff) return false;
    return true;
  }

  function isPublicIpAddress(value) {
    return value.includes(":") ? isPublicIPv6(value) : isPublicIPv4(value);
  }

  const api = { isPublicIpAddress };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.TraceAtlasTargetValidation = api;
})(typeof window === "undefined" ? null : window);
