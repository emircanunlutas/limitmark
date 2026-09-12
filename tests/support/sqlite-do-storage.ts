import { DatabaseSync } from "node:sqlite";
import type { DurableStorageLike, SqlCursorLike } from "../../workers/admission-service/authority";

export class NodeSqliteDurableStorage implements DurableStorageLike {
  readonly database: DatabaseSync;
  readonly sql;
  constructor(path = ":memory:") {
    this.database = new DatabaseSync(path);
    this.sql = {
      exec: <T>(query: string, ...bindings: unknown[]): SqlCursorLike<T> => {
        const result = this.database.prepare(query).all(...bindings as never[]) as T[];
        return Object.assign(result, { toArray: () => result });
      },
    };
  }
  transactionSync<T>(callback: () => T): T {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = callback();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
  count(table: "observations" | "nonces"): number {
    return Number((this.database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count);
  }
  close(): void { this.database.close(); }
}
