/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    relative: true,
    files: [
      "./src/app/templates/**/*.html",
      "./src/app/static/js/**/*.js",
      "./node_modules/flowbite/**/*.js",
      "./node_modules/preline/dist/*.js",
      "./node_modules/tw-elements/dist/js/**/*.js",
    ],
  },
  theme: {
    extend: {
      keyframes: {
        fadeOut: {
          "0%": {opacity: "1"},
          "50%": {opacity: "0.5"},
          "100%": {opacity: "0", display: "none"}
        },
        wipeUp: {
          "0%": {
            transform: "scaleY(1)", 
            transformOrigin: "top",
          },
          "50%": {
            transform: "scaleY(0.5)",
            transformOrigin: "top",
            opacity: "0.5"
          },
          "75%": {
            transform: "scaleY(0.25)",
            transformOrigin: "top",
            opacity: "0.25"
          },
          "100%": {
            transform: "scaleY(0.01)",
            transformOrigin: "top",
            opacity: "0",
            display: "none",
          }
        },
        sweepRight: {
          "0%": {width: "0%"},
          "50%": {width: "50%"},
          "100%": {width: "100%"}
        },
        dropDown: {
          "0%": {top: "0rem", opacity: "0"},
          "50%": {top: "1.5rem", opacity: "0.5"},
          "100%": {top: "3rem", opacity: "1"}
        },
        highlight: {
          "0%": {backgroundColor: "initial"},
          "50%": {backgroundColor: "#e9d2fd"},
          "100%": {backgroundColor: "initial"} 
        }
      },
      animation: {
        "spin-fast": "spin 0.7s linear infinite",
        "fade-out": "fadeOut 0.9s linear 1 forwards",
        "wipe-up": "wipeUp 0.9s linear 1 forwards",
        "sweep-right": "sweepRight 1.5s linear 1 backwards",
        "drop-down": "dropDown 0.5s linear 1 forwards",
        "highlight": "highlight 2s linear 1 forwards",
      },
      colors: {
        main: {
          50: "#eaa7c7",
          100: "#eaa7c7",
          200: "#eaa7c7",
          300: "#eaa7c7",
          400: "#c68d9d",
          500: "#bc6d87",
          600: "#bc6d87",
          700: "#ac5a71",
          800: "#ac5a71",
          900: "#ac5a71",
        },
        highlighted: "#e9d2fd",
      },
      width: {
        68: "68px",
        88: "88px",
        275: "275px",
        290: "290px",
        350: "350px",
        600: "600px",
      },
      boxShadow: {
        "around": "0 2px 12px rgba(0, 0, 0, 0.2)"
      }
    },
  },
  plugins: [
    require("tw-elements/dist/plugin"),
    require("preline/plugin"),
    require("flowbite/plugin"),
    require("daisyui"),
  ],
}