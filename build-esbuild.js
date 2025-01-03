import * as esbuild from 'esbuild'

const result = await esbuild.build({
	entryPoints: ["src/test.ts"],
	bundle: true,
	platform: "node",
	format: "esm",
	define: {
		"NO_THREAD_ASSERTIONS": "true",
	},
	outdir: "dist/esbuild"
})