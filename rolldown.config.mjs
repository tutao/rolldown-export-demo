import { defineConfig } from "rolldown";

export default defineConfig({
  input: ["./src/start.ts", "./src/end.ts"],
  platform: "node",
  output: {
    format: "cjs",
    dir: "dist",
  },
});
