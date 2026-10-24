const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("EvidenceTracker Smart Contract", function () {
  let evidenceTracker;
  let admin, analyst, collector, auditor, unauthorized;
  const sampleEvidenceHash = ethers.keccak256(ethers.toUtf8Bytes("EVIDENCE_CONTENT_01"));
  const sampleRawHash = ethers.keccak256(ethers.toUtf8Bytes("RAW_PCAP_STREAM_01"));
  const sampleMerkleRoot = ethers.keccak256(ethers.toUtf8Bytes("MERKLE_ROOT_01"));
  const newEvidenceHash = ethers.keccak256(ethers.toUtf8Bytes("EVIDENCE_CONTENT_02"));

  beforeEach(async function () {
    [admin, analyst, collector, auditor, unauthorized] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("EvidenceTracker");
    evidenceTracker = await Factory.deploy();
    await evidenceTracker.waitForDeployment();

    const ANALYST_ROLE = await evidenceTracker.ANALYST_ROLE();
    await evidenceTracker.grantRole(ANALYST_ROLE, analyst.address);

    const AUDITOR_ROLE = await evidenceTracker.AUDITOR_ROLE();
    await evidenceTracker.grantRole(AUDITOR_ROLE, auditor.address);
  });

  it("Allows analyst to anchor evidence and emits EvidenceStored event", async function () {
    const tx = await evidenceTracker.connect(analyst).storeEvidence(
      sampleEvidenceHash,
      sampleRawHash,
      sampleMerkleRoot,
      "INSA-CR-2026-001",
      "DDoS",
      "EthioTelecom-GW",
      "Nathenael Ermias",
      "ipfs://QmHash1"
    );

    await expect(tx)
      .to.emit(evidenceTracker, "EvidenceStored");

    const count = await evidenceTracker.totalEvidenceCount();
    expect(count).to.equal(1n);
  });

  it("Rejects anchoring from unauthorized address", async function () {
    await expect(
      evidenceTracker.connect(unauthorized).storeEvidence(
        sampleEvidenceHash,
        sampleRawHash,
        sampleMerkleRoot,
        "INSA-CR-2026-001",
        "DDoS",
        "EthioTelecom-GW",
        "Nathenael Ermias",
        "ipfs://QmHash1"
      )
    ).to.be.revertedWith("SecureEvidence: Unauthorized role");
  });

  it("Blocks writes when contract is paused and restores when unpaused", async function () {
    await evidenceTracker.connect(admin).togglePause();
    expect(await evidenceTracker.paused()).to.equal(true);

    await expect(
      evidenceTracker.connect(analyst).storeEvidence(
        sampleEvidenceHash,
        sampleRawHash,
        sampleMerkleRoot,
        "INSA-CR-2026-001",
        "DDoS",
        "EthioTelecom-GW",
        "Nathenael Ermias",
        "ipfs://QmHash1"
      )
    ).to.be.revertedWith("SecureEvidence: Contract operations are paused");

    await evidenceTracker.connect(admin).togglePause();
    expect(await evidenceTracker.paused()).to.equal(false);

    await expect(
      evidenceTracker.connect(analyst).storeEvidence(
        sampleEvidenceHash,
        sampleRawHash,
        sampleMerkleRoot,
        "INSA-CR-2026-001",
        "DDoS",
        "EthioTelecom-GW",
        "Nathenael Ermias",
        "ipfs://QmHash1"
      )
    ).to.not.be.reverted;
  });

  it("Supports superseding evidence without deleting history", async function () {
    await evidenceTracker.connect(analyst).storeEvidence(
      sampleEvidenceHash,
      sampleRawHash,
      sampleMerkleRoot,
      "INSA-CR-2026-001",
      "DDoS",
      "EthioTelecom-GW",
      "Nathenael Ermias",
      "ipfs://QmHash1"
    );

    await evidenceTracker.connect(analyst).storeEvidence(
      newEvidenceHash,
      sampleRawHash,
      sampleMerkleRoot,
      "INSA-CR-2026-001",
      "DDoS-Amended",
      "EthioTelecom-GW",
      "Nathenael Ermias",
      "ipfs://QmHash2"
    );

    const tx = await evidenceTracker.connect(analyst).supersedeEvidence(
      sampleEvidenceHash,
      newEvidenceHash,
      "Amended forensic telemetry analysis"
    );

    await expect(tx)
      .to.emit(evidenceTracker, "EvidenceSuperseded")
      .withArgs(
        sampleEvidenceHash,
        newEvidenceHash,
        "INSA-CR-2026-001",
        analyst.address,
        "Amended forensic telemetry analysis"
      );

    const rec = await evidenceTracker.getEvidenceRecord(sampleEvidenceHash);
    expect(rec.status).to.equal(1n); // RecordStatus.SUPERSEDED
    expect(rec.supersededBy).to.equal(newEvidenceHash);
  });

  it("Verifies an authentic anchored evidence hash", async function () {
    await evidenceTracker.connect(analyst).storeEvidence(
      sampleEvidenceHash,
      sampleRawHash,
      sampleMerkleRoot,
      "INSA-CR-2026-001",
      "DDoS",
      "EthioTelecom-GW",
      "Nathenael Ermias",
      "ipfs://QmHash1"
    );

    const res = await evidenceTracker.verifyEvidence.staticCall(sampleEvidenceHash);
    expect(res[0]).to.equal(true); // isAuthentic
    expect(res[1]).to.equal(false); // isSuperseded
    expect(res[2]).to.equal("INSA-CR-2026-001"); // caseId
  });

  it("Rejects verification for unanchored hash", async function () {
    const unknownHash = ethers.keccak256(ethers.toUtf8Bytes("RANDOM_HASH"));
    const res = await evidenceTracker.verifyEvidence.staticCall(unknownHash);
    expect(res[0]).to.equal(false);
  });

  // --- Per-role permissions ---
  it("Admin can grant and revoke roles", async function () {
    const AUDITOR_ROLE = await evidenceTracker.AUDITOR_ROLE();
    await expect(
      evidenceTracker.connect(admin).grantRole(AUDITOR_ROLE, collector.address)
    ).to.emit(evidenceTracker, "RoleGranted")
      .withArgs(AUDITOR_ROLE, collector.address, admin.address);

    await expect(
      evidenceTracker.connect(admin).revokeRole(AUDITOR_ROLE, collector.address)
    ).to.emit(evidenceTracker, "RoleRevoked")
      .withArgs(AUDITOR_ROLE, collector.address, admin.address);
  });

  it("Collector role cannot anchor evidence (only ANALYST_ROLE can)", async function () {
    const COLLECTOR_ROLE = await evidenceTracker.COLLECTOR_ROLE();
    await evidenceTracker.connect(admin).grantRole(COLLECTOR_ROLE, collector.address);
    await expect(
      evidenceTracker.connect(collector).storeEvidence(
        sampleEvidenceHash, sampleRawHash, sampleMerkleRoot,
        "INSA-CR-PERM-01", "DDoS", "EthioTelecom-GW", "Collector", "ipfs://Qm"
      )
    ).to.be.revertedWith("SecureEvidence: Unauthorized role");
  });

  it("Admin can revoke analyst role and that address is then blocked", async function () {
    const ANALYST_ROLE = await evidenceTracker.ANALYST_ROLE();
    await evidenceTracker.connect(admin).revokeRole(ANALYST_ROLE, analyst.address);
    await expect(
      evidenceTracker.connect(analyst).storeEvidence(
        sampleEvidenceHash, sampleRawHash, sampleMerkleRoot,
        "INSA-CR-PERM-02", "DDoS", "EthioTelecom-GW", "Analyst", "ipfs://Qm"
      )
    ).to.be.revertedWith("SecureEvidence: Unauthorized role");
  });

  // --- Merkle valid/invalid proof ---
  it("EvidenceStored event carries the correct merkleRoot value", async function () {
    const leafHash = ethers.keccak256(ethers.toUtf8Bytes("LEAF_01"));
    const sibling  = ethers.keccak256(ethers.toUtf8Bytes("LEAF_02"));
    const sorted = leafHash < sibling ? [leafHash, sibling] : [sibling, leafHash];
    const merkleRoot = ethers.keccak256(ethers.concat(sorted));

    const tx = await evidenceTracker.connect(analyst).storeEvidence(
      leafHash, sampleRawHash, merkleRoot,
      "INSA-CR-MERKLE-01", "PortScan", "NBE-GW", "Nathenael", "ipfs://Qm"
    );

    await expect(tx).to.emit(evidenceTracker, "EvidenceStored");
    const rec = await evidenceTracker.getEvidenceRecord(leafHash);
    expect(rec.merkleRoot).to.equal(merkleRoot);
  });

  it("Leaf not in root does not match (invalid Merkle path)", async function () {
    const realLeaf = ethers.keccak256(ethers.toUtf8Bytes("REAL_LEAF"));
    const fakeLeaf = ethers.keccak256(ethers.toUtf8Bytes("FAKE_LEAF"));
    const sibling  = ethers.keccak256(ethers.toUtf8Bytes("LEAF_02"));
    const sorted   = realLeaf < sibling ? [realLeaf, sibling] : [sibling, realLeaf];
    const merkleRoot = ethers.keccak256(ethers.concat(sorted));

    const sortedFake = fakeLeaf < sibling ? [fakeLeaf, sibling] : [sibling, fakeLeaf];
    const fakeRoot = ethers.keccak256(ethers.concat(sortedFake));
    expect(fakeRoot).to.not.equal(merkleRoot);
  });

  it("EvidenceStored event carries correct evidenceHash, caseId and officer address", async function () {
    const tx = await evidenceTracker.connect(analyst).storeEvidence(
      sampleEvidenceHash, sampleRawHash, sampleMerkleRoot,
      "INSA-CR-EVENT-01", "DDoS", "CBE-GW", "Nathenael Ermias", "ipfs://QmEvent"
    );
    const receipt = await tx.wait();
    const event = receipt.logs
      .map(log => { try { return evidenceTracker.interface.parseLog(log); } catch { return null; } })
      .find(e => e && e.name === "EvidenceStored");

    expect(event).to.not.be.null;
    expect(event.args.evidenceHash).to.equal(sampleEvidenceHash);
    expect(event.args.caseId.hash).to.equal(ethers.id("INSA-CR-EVENT-01"));
    expect(event.args.officerAddress).to.equal(analyst.address);
  });

  // --- A1: anchorLedgerHead and getLatestHead ---
  describe("Ledger Head Anchoring", function () {
    const headHash1 = ethers.keccak256(ethers.toUtf8Bytes("LEDGER_HEAD_BLOCK_10"));
    const headHash2 = ethers.keccak256(ethers.toUtf8Bytes("LEDGER_HEAD_BLOCK_20"));

    it("Admin can anchor ledger head and emits LedgerHeadAnchored event", async function () {
      const tx = await evidenceTracker.connect(admin).anchorLedgerHead(headHash1, 10);
      await expect(tx)
        .to.emit(evidenceTracker, "LedgerHeadAnchored")
        .withArgs(headHash1, 10n, admin.address, (await ethers.provider.getBlock(tx.blockNumber)).timestamp, tx.blockNumber);

      const latest = await evidenceTracker.getLatestHead();
      expect(latest.headHash).to.equal(headHash1);
      expect(latest.recordCount).to.equal(10n);
      expect(latest.submitter).to.equal(admin.address);
    });

    it("Auditor can anchor ledger head with increased recordCount", async function () {
      await evidenceTracker.connect(admin).anchorLedgerHead(headHash1, 10);

      const tx = await evidenceTracker.connect(auditor).anchorLedgerHead(headHash2, 20);
      await expect(tx)
        .to.emit(evidenceTracker, "LedgerHeadAnchored")
        .withArgs(headHash2, 20n, auditor.address, (await ethers.provider.getBlock(tx.blockNumber)).timestamp, tx.blockNumber);

      const latest = await evidenceTracker.getLatestHead();
      expect(latest.headHash).to.equal(headHash2);
      expect(latest.recordCount).to.equal(20n);
      expect(latest.submitter).to.equal(auditor.address);
    });

    it("Rejects non-auditor / non-admin from anchoring ledger head", async function () {
      await expect(
        evidenceTracker.connect(analyst).anchorLedgerHead(headHash1, 10)
      ).to.be.revertedWith("SecureEvidence: Unauthorized role");

      await expect(
        evidenceTracker.connect(unauthorized).anchorLedgerHead(headHash1, 10)
      ).to.be.revertedWith("SecureEvidence: Unauthorized role");
    });

    it("Rejects decreased recordCount (monotonic count enforcement)", async function () {
      await evidenceTracker.connect(admin).anchorLedgerHead(headHash1, 15);

      await expect(
        evidenceTracker.connect(admin).anchorLedgerHead(headHash2, 14)
      ).to.be.revertedWith("Record count cannot decrease");

      // Same count is allowed
      await expect(
        evidenceTracker.connect(admin).anchorLedgerHead(headHash2, 15)
      ).to.not.be.reverted;
    });

    it("Rejects zero head hash", async function () {
      await expect(
        evidenceTracker.connect(admin).anchorLedgerHead(ethers.ZeroHash, 10)
      ).to.be.revertedWith("Invalid head hash");
    });
  });
});
