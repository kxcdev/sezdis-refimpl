import { defineConfig, Options } from "tsup";

export default defineConfig((options: Options) => ({
  entry: {
    index: "index.ts",
  },
  ignoreWatch: ["_tsout"],
  banner: {
    js: "'use client'",
  },
  clean: true,
  format: ["cjs", "esm"],
  external: [],
  dts: true,
  ...options,
}));
