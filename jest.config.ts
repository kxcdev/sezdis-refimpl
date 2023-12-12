import type { Config } from "jest";

const config: Config = {
  verbose: true,
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        // ts-jest configuration goes here
      },
    ],
  },
};

export default config;
