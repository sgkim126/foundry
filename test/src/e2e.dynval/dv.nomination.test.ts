// Copyright 2019 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import * as chai from "chai";
import { expect } from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { H512 } from "codechain-primitives/lib";
import * as stake from "codechain-stakeholder-sdk";
import "mocha";

import { validators as originalDynValidators } from "../../tendermint.dynval/constants";
import { PromiseExpect } from "../helper/promise";
import { selfNominate, setTermTestTimeout, withNodes } from "./setup";

chai.use(chaiAsPromised);

const [alice, ...otherDynValidators] = originalDynValidators;

describe("Nomination", function() {
    const promiseExpect = new PromiseExpect();
    const NOMINATION_EXPIRATION = 2;

    describe("Alice doesn't self nominate in NOMINATION_EXPIRATION", async function() {
        // alice : Elected as a validator, but does not send precommits and does not propose.
        //   Alice should be jailed.
        // betty : Not elected as validator because of small delegation. She acquire more delegation in the first term.
        //   betty should be a validator in the second term.
        const { nodes } = withNodes(this, {
            promiseExpect,
            overrideParams: {
                nominationExpiration: NOMINATION_EXPIRATION
            },
            validators: [
                { signer: alice },
                ...otherDynValidators.map((validator, index) => ({
                    signer: validator,
                    delegation: 5000 - index,
                    deposit: 100000
                }))
            ]
        });

        it("Alice be eligible after 2 terms", async function() {
            const termWaiter = setTermTestTimeout(this, {
                terms: 3
            });

            const [aliceNode, ...otherDynNodes] = nodes;

            const selfNominationHash = await selfNominate(
                aliceNode.sdk,
                alice,
                10
            );
            await aliceNode.waitForTx(selfNominationHash);

            const beforeCandidates = await stake.getCandidates(
                otherDynNodes[0].sdk
            );

            expect(
                beforeCandidates.map(candidate => candidate.pubkey.toString())
            ).to.includes(H512.ensure(alice.publicKey).toString());

            await termWaiter.waitNodeUntilTerm(otherDynNodes[0], {
                target: 4,
                termPeriods: 3
            });

            const [validators, banned, candidates, jailed] = await Promise.all([
                stake.getValidators(otherDynNodes[0].sdk),
                stake.getBanned(otherDynNodes[0].sdk),
                stake.getCandidates(otherDynNodes[0].sdk),
                stake.getJailed(otherDynNodes[0].sdk)
            ]);

            expect(
                validators.map(validator => validator.pubkey.toString())
            ).not.to.includes(alice.publicKey);
            expect(
                banned.map(ban => ban.getAccountId().toString())
            ).not.to.includes(alice.accountId);
            expect(
                candidates.map(canidate => canidate.pubkey.toString())
            ).not.to.includes(alice.publicKey);
            expect(jailed.map(jail => jail.address)).not.to.includes(
                alice.platformAddress.toString()
            );
        });
    });

    afterEach(function() {
        promiseExpect.checkFulfilled();
    });
});