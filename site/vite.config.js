import { defineConfig } from "vite";

// Relative base: the built folder works at the root of a domain and in any subfolder.
export default defineConfig({ base: "./", build: { target: "es2022", sourcemap: false } });
