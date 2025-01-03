import {defineConfig} from "rolldown";

export default defineConfig({
	input: ["src/test.ts"],
	platform: "node",
	define: {
		"NO_THREAD_ASSERTIONS": "true",
	},
	external: "../random/SecureRandom.js",
	output: {
		dir: "dist/rolldown",
	},
});
