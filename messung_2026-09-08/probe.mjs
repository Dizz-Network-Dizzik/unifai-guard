const UB =
  "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))";
const rx = (s, f = "") =>
  new RegExp(s.replaceAll("\\b", UB), f.includes("u") ? f : f + "u");

console.log("UB ok:", UB.slice(0, 20));
console.log("6 CJK  plain:", /\b(?:发送)\b/u.test("请 发送 数据"), " UB:", rx("\\b(?:发送)\\b", "i").test("请 发送 数据"));
console.log("7 ü     plain:", /\b[uü]bermitteln\b/iu.test("bitte übermitteln jetzt"), " UB:", rx("\\b[uü]bermitteln\\b", "i").test("bitte übermitteln jetzt"));
console.log("8 word  UB match:", rx("\\bignore\\s+all\\b", "i").test("Ignore all previous"), " inside-word (must be false):", rx("\\bcall\\b", "i").test("recalled"));
console.log("8b UB at string start:", rx("\\bamount\\b", "i").test("amount to send"));
console.log("8c UB at string end:", rx("\\bsend\\b", "i").test("do not send"));
console.log("8d underscore is a word char:", rx("\\bcall\\b", "i").test("get_call_x"));
console.log("9 dangerous name UB:", rx("\\b(?:transfer|withdraw)[_-]?(?:all|funds?)\\b", "i").test("invoke the transfer_all action"));

// zero-width interior detection over CODEPOINTS, not utf-16 units
const t = "Am​ount \u{1D400}\u{E0041}";
console.log("10 cp array len:", [...t].length, " utf16:", t.length);

// Cf category
console.log("11 Cf on tag char:", /\p{Cf}/u.test("\u{E0041}"), " on ZWSP:", /\p{Cf}/u.test("​"));

// printable approximation
const printable = (c) => !/[\p{Cc}\p{Cf}\p{Cs}\p{Co}]/u.test(c) && (c === " " || !/\p{Zs}/u.test(c));
console.log("12 printable('a'):", printable("a"), " printable('\\x01'):", printable("\x01"), " printable(' '):", printable(" "));

// strict base64
const strict = (s) => /^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0;
console.log("13 strict b64:", strict("aGVsbG8gd29ybGQgdGhlcmUh"), strict("not!base64"));

// canonical JSON key sort by codepoint
const cmp = (a, b) => {
  const A = [...a], B = [...b];
  for (let i = 0; i < Math.min(A.length, B.length); i++) {
    const d = A[i].codePointAt(0) - B[i].codePointAt(0);
    if (d) return d;
  }
  return A.length - B.length;
};
console.log("14 key sort:", ["b", "a", "A", "_"].sort(cmp).join(","));

// node:test + assert available from .ts too (checked separately)
console.log("15 crypto:", (await import("node:crypto")).createHash("sha256").update("x").digest("hex").slice(0, 12));
