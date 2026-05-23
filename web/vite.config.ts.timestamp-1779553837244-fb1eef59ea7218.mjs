// vite.config.ts
import path from "path";
import { defineConfig } from "file:///Users/asif/Desktop/untitled%20folder%206/sentinel/web/node_modules/.pnpm/vite@5.4.21_@types+node@22.19.19_lightningcss@1.32.0/node_modules/vite/dist/node/index.js";
import react from "file:///Users/asif/Desktop/untitled%20folder%206/sentinel/web/node_modules/.pnpm/@vitejs+plugin-react@4.7.0_vite@5.4.21_@types+node@22.19.19_lightningcss@1.32.0_/node_modules/@vitejs/plugin-react/dist/index.js";
import tailwindcss from "file:///Users/asif/Desktop/untitled%20folder%206/sentinel/web/node_modules/.pnpm/@tailwindcss+vite@4.3.0_vite@5.4.21_@types+node@22.19.19_lightningcss@1.32.0_/node_modules/@tailwindcss/vite/dist/index.mjs";
var __vite_injected_original_dirname = "/Users/asif/Desktop/untitled folder 6/sentinel/web";
var vite_config_default = defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__vite_injected_original_dirname, "./src") }
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/ws": { target: "ws://localhost:8080", ws: true }
    }
  },
  build: { outDir: "dist", chunkSizeWarningLimit: 2e3 }
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvVXNlcnMvYXNpZi9EZXNrdG9wL3VudGl0bGVkIGZvbGRlciA2L3NlbnRpbmVsL3dlYlwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL1VzZXJzL2FzaWYvRGVza3RvcC91bnRpdGxlZCBmb2xkZXIgNi9zZW50aW5lbC93ZWIvdml0ZS5jb25maWcudHNcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfaW1wb3J0X21ldGFfdXJsID0gXCJmaWxlOi8vL1VzZXJzL2FzaWYvRGVza3RvcC91bnRpdGxlZCUyMGZvbGRlciUyMDYvc2VudGluZWwvd2ViL3ZpdGUuY29uZmlnLnRzXCI7aW1wb3J0IHBhdGggZnJvbSBcInBhdGhcIjtcbmltcG9ydCB7IGRlZmluZUNvbmZpZyB9IGZyb20gXCJ2aXRlXCI7XG5pbXBvcnQgcmVhY3QgZnJvbSBcIkB2aXRlanMvcGx1Z2luLXJlYWN0XCI7XG5pbXBvcnQgdGFpbHdpbmRjc3MgZnJvbSBcIkB0YWlsd2luZGNzcy92aXRlXCI7XG5cbi8vIERldiBwcm94aWVzIEFQSSArIFdlYlNvY2tldCB0byB0aGUgR28gc2VydmVyOyBwcm9kdWN0aW9uIGJ1aWxkIGlzIHNlcnZlZCBmcm9tIHRoZVxuLy8gc2FtZSBvcmlnaW4gYnkgdGhlIHNlcnZlciwgc28gYWxsIGNsaWVudCBVUkxzIGFyZSByZWxhdGl2ZS5cbmV4cG9ydCBkZWZhdWx0IGRlZmluZUNvbmZpZyh7XG4gIHBsdWdpbnM6IFtyZWFjdCgpLCB0YWlsd2luZGNzcygpXSxcbiAgcmVzb2x2ZToge1xuICAgIGFsaWFzOiB7IFwiQFwiOiBwYXRoLnJlc29sdmUoX19kaXJuYW1lLCBcIi4vc3JjXCIpIH0sXG4gIH0sXG4gIHNlcnZlcjoge1xuICAgIHBvcnQ6IDUxNzMsXG4gICAgcHJveHk6IHtcbiAgICAgIFwiL2FwaVwiOiB7IHRhcmdldDogXCJodHRwOi8vbG9jYWxob3N0OjgwODBcIiwgY2hhbmdlT3JpZ2luOiB0cnVlIH0sXG4gICAgICBcIi93c1wiOiB7IHRhcmdldDogXCJ3czovL2xvY2FsaG9zdDo4MDgwXCIsIHdzOiB0cnVlIH0sXG4gICAgfSxcbiAgfSxcbiAgYnVpbGQ6IHsgb3V0RGlyOiBcImRpc3RcIiwgY2h1bmtTaXplV2FybmluZ0xpbWl0OiAyMDAwIH0sXG59KTtcbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBNFUsT0FBTyxVQUFVO0FBQzdWLFNBQVMsb0JBQW9CO0FBQzdCLE9BQU8sV0FBVztBQUNsQixPQUFPLGlCQUFpQjtBQUh4QixJQUFNLG1DQUFtQztBQU96QyxJQUFPLHNCQUFRLGFBQWE7QUFBQSxFQUMxQixTQUFTLENBQUMsTUFBTSxHQUFHLFlBQVksQ0FBQztBQUFBLEVBQ2hDLFNBQVM7QUFBQSxJQUNQLE9BQU8sRUFBRSxLQUFLLEtBQUssUUFBUSxrQ0FBVyxPQUFPLEVBQUU7QUFBQSxFQUNqRDtBQUFBLEVBQ0EsUUFBUTtBQUFBLElBQ04sTUFBTTtBQUFBLElBQ04sT0FBTztBQUFBLE1BQ0wsUUFBUSxFQUFFLFFBQVEseUJBQXlCLGNBQWMsS0FBSztBQUFBLE1BQzlELE9BQU8sRUFBRSxRQUFRLHVCQUF1QixJQUFJLEtBQUs7QUFBQSxJQUNuRDtBQUFBLEVBQ0Y7QUFBQSxFQUNBLE9BQU8sRUFBRSxRQUFRLFFBQVEsdUJBQXVCLElBQUs7QUFDdkQsQ0FBQzsiLAogICJuYW1lcyI6IFtdCn0K
