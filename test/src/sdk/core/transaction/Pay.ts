import { Address, U64 } from "../classes";
import { Transaction } from "../Transaction";
import { NetworkId } from "../types";

export interface PayActionJSON {
    receiver: string;
    quantity: string;
}

export class Pay extends Transaction {
    private readonly receiver: Address;
    private readonly quantity: U64;

    public constructor(receiver: Address, quantity: U64, networkId: NetworkId) {
        super(networkId);
        this.receiver = receiver;
        this.quantity = quantity;
    }

    public type(): string {
        return "pay";
    }

    protected actionToEncodeObject(): any[] {
        return [
            2,
            this.receiver.getPubKey().toEncodeObject(),
            this.quantity.toEncodeObject()
        ];
    }

    protected actionToJSON(): PayActionJSON {
        return {
            receiver: this.receiver.value,
            quantity: this.quantity.toJSON()
        };
    }
}
