import { describe, it } from "vite-plus/test";
import { memoryGnapStore } from "../../src/gnap/server/index";
import { storeContract } from "../../src/gnap/server/testing/index";

storeContract({ describe, it }, "memoryGnapStore", () => memoryGnapStore());
