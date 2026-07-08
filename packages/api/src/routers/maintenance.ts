import { adminOr404Procedure } from "../index";
import {
  backfillLegacyEnumColumns,
  getLegacyEnumBackfillStatus,
} from "../lib/legacy-enum-backfill";

export const maintenanceRouter = {
  legacyEnumBackfillStatus: adminOr404Procedure.handler(async () => {
    return await getLegacyEnumBackfillStatus();
  }),

  backfillLegacyEnums: adminOr404Procedure.handler(async () => {
    const result = await backfillLegacyEnumColumns();
    console.info("[maintenance] legacy enum backfill completed", result);
    return result;
  }),
};
