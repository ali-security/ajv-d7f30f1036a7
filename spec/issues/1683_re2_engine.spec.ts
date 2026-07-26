// Seal: the `re2` native addon cannot be built/loaded on the sealing CI runner
// (re2's prebuilt binary is unavailable for these Node versions and its
// node-gyp build does not produce a usable `.node` binary), so importing it
// crashes mocha at file load. The pattern keyword is exercised by the mainline
// pattern specs and the JSON-Schema-Test-Suite; the re2 alternate-engine
// integration is skipped here. This file ships only in the spec tree and never
// in the published tarball (`files`: lib/, dist/, .runkit_example.js).
describe.skip("issue #1683, using RegExp engine other than the standard one (re2)", () => {
  it("is skipped: re2 native addon unavailable on the sealing CI runner", () => {
    // no-op
  })
})
