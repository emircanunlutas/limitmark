import type {
  NotificationAdapter,
  NotificationCommand,
  NotificationDeliveryResult,
} from "../../src/lib/notification-adapter";

export type SyntheticDeliveryBehavior =
  | NotificationDeliveryResult
  | "throw"
  | ((command: NotificationCommand) => NotificationDeliveryResult | Promise<NotificationDeliveryResult>);

export class SyntheticNotificationAdapter implements NotificationAdapter {
  readonly commands: NotificationCommand[] = [];

  constructor(
    private readonly behavior: SyntheticDeliveryBehavior = { outcome: "delivered" },
    private readonly delayMs = 0,
  ) {}

  async deliver(command: NotificationCommand): Promise<NotificationDeliveryResult> {
    this.commands.push(command);
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    if (this.behavior === "throw") throw new Error("synthetic provider detail must not persist");
    return typeof this.behavior === "function"
      ? this.behavior(command)
      : this.behavior;
  }
}
