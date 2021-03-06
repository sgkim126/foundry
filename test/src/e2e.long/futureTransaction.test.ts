// Copyright 2018-2019 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import "mocha";
import { PromiseExpect } from "../helper/promise";
import CodeChain from "../helper/spawn";

describe("Handle future transactions", function() {
    let nodeA: CodeChain;
    const promiseExpect = new PromiseExpect();

    beforeEach(async function() {
        nodeA = new CodeChain();

        await nodeA.start({ argv: ["--no-tx-relay"] });
    });

    it("Alone", async function() {
        const sending = [];
        for (let i = 0; i < 10; i++) {
            sending.push(nodeA.sendPayTx({ seq: 9 - i }));
        }
        await Promise.all(sending);
    }).timeout(10_000);

    describe("Two nodes", function() {
        let nodeB: CodeChain;

        beforeEach(async function() {
            this.timeout(60_000);
            nodeB = new CodeChain();
            await nodeB.start({ argv: ["--no-tx-relay"] });
            await promiseExpect.shouldFulfill("connect", nodeB.connect(nodeA));
        });

        it("ping pong", async function() {
            const sending = [];
            for (let i = 0; i < 10; i++) {
                if (i % 2 === 0) {
                    sending.push(nodeA.sendPayTx({ seq: 9 - i }));
                } else {
                    sending.push(nodeB.sendPayTx({ seq: 9 - i }));
                }
            }
            await promiseExpect.shouldFulfill("Payment", Promise.all(sending));
        }).timeout(20_000);

        afterEach(async function() {
            if (this.currentTest!.state === "failed") {
                nodeB.keepLogs();
            }
            promiseExpect.checkFulfilled();
            await nodeB.clean();
        });
    });

    afterEach(async function() {
        if (this.currentTest!.state === "failed") {
            nodeA.keepLogs();
        }
        await nodeA.clean();
    });
});
