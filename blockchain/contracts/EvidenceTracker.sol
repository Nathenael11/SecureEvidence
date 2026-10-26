// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceTracker
 * @dev Sovereign Cyber Forensics Evidence Ledger for INSA (Ethiopia)
 * @author Nathenael Ermias nathenaelermias13@gmail.com
 * @notice Implements tamper-proof forensic evidence anchoring, cryptographic
 *         inclusion proofs, role-based access control, and record supersession.
 *         Complies with FDRE Computer Crime Proclamation (No. 958/2016)
 *         and Electronic Signature Proclamation (No. 1072/2018).
 */
contract EvidenceTracker {

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");
    bytes32 public constant COLLECTOR_ROLE = keccak256("COLLECTOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    enum RecordStatus { ACTIVE, SUPERSEDED, REVOKED }

    struct EvidenceRecord {
        bytes32 evidenceHash;      // SHA-256 digest of forensic evidence packet
        bytes32 rawArtifactHash;   // SHA-256 digest of original raw artifact (PCAP/Log)
        bytes32 merkleRoot;        // Merkle root if part of batch, or bytes32(0)
        string caseId;             // Unique INSA case identifier
        string incidentType;       // Threat category (DDoS, Botnet, PortScan, etc.)
        string targetAsset;        // Ethiopian critical asset impacted
        string investigatorName;   // Certified INSA forensics officer
        address officerAddress;    // Ethereum/Besu address of submitting officer
        uint256 timestamp;         // Block timestamp when registered
        uint256 blockNumber;       // Block height for judicial audit
        string metadataUri;        // Off-chain encrypted storage pointer (IPFS/Swarm/Vault)
        RecordStatus status;       // ACTIVE, SUPERSEDED, REVOKED
        bytes32 supersededBy;      // Hash of superseding record if applicable
        bool exists;
    }

    address public admin;
    bool public paused;
    string public constant AGENCY_NAME = "Information Network Security Administration (INSA)";
    string public constant LEGAL_FRAMEWORK = "FDRE Proclamations No. 958/2016 & No. 1072/2018";

    // Role mappings: role => address => bool
    mapping(bytes32 => mapping(address => bool)) private _roles;

    // Mapping from Evidence Hash -> Evidence Record
    mapping(bytes32 => EvidenceRecord) private evidenceRegistry;

    // Mapping from Case ID -> List of Evidence Hashes
    mapping(string => bytes32[]) private caseEvidenceMap;

    uint256 public totalEvidenceCount;

    struct LedgerHead {
        bytes32 headHash;
        uint256 recordCount;
        uint256 timestamp;
        uint256 blockNumber;
        address submitter;
        bool exists;
    }

    LedgerHead public latestHead;

    // Events for forensic court audit trail
    event EvidenceStored(
        bytes32 indexed evidenceHash,
        bytes32 indexed rawArtifactHash,
        string indexed caseId,
        string incidentType,
        address officerAddress,
        uint256 timestamp,
        uint256 blockNumber
    );

    event EvidenceSuperseded(
        bytes32 indexed oldEvidenceHash,
        bytes32 indexed newEvidenceHash,
        string caseId,
        address officerAddress,
        string reason
    );

    event EvidenceRevoked(
        bytes32 indexed evidenceHash,
        string caseId,
        address officerAddress,
        string reason
    );

    event EvidenceVerified(
        bytes32 indexed evidenceHash,
        bool isAuthentic,
        string caseId,
        uint256 verificationTime
    );

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event EmergencyPauseToggled(bool isPaused, address indexed admin);

    event LedgerHeadAnchored(
        bytes32 indexed headHash,
        uint256 indexed recordCount,
        address indexed submitter,
        uint256 timestamp,
        uint256 blockNumber
    );

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender] || msg.sender == admin, "SecureEvidence: Unauthorized role");
        _;
    }

    modifier onlyAuditorOrAdmin() {
        require(
            _roles[AUDITOR_ROLE][msg.sender] ||
            _roles[ADMIN_ROLE][msg.sender] ||
            msg.sender == admin,
            "SecureEvidence: Unauthorized role"
        );
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "SecureEvidence: Contract operations are paused");
        _;
    }

    constructor() {
        admin = msg.sender;
        _roles[ADMIN_ROLE][msg.sender] = true;
        _roles[ANALYST_ROLE][msg.sender] = true;
        _roles[COLLECTOR_ROLE][msg.sender] = true;
        _roles[AUDITOR_ROLE][msg.sender] = true;
    }

    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _roles[role][account] = true;
        emit RoleGranted(role, account, msg.sender);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    function togglePause() external onlyRole(ADMIN_ROLE) {
        paused = !paused;
        emit EmergencyPauseToggled(paused, msg.sender);
    }

    /**
     * @notice Anchor forensic evidence fingerprint onto the sovereign ledger.
     */
    function storeEvidence(
        bytes32 evidenceHash,
        bytes32 rawArtifactHash,
        bytes32 merkleRoot,
        string calldata caseId,
        string calldata incidentType,
        string calldata targetAsset,
        string calldata investigatorName,
        string calldata metadataUri
    ) external onlyRole(ANALYST_ROLE) whenNotPaused returns (bool) {
        require(evidenceHash != bytes32(0), "Invalid evidence hash");
        require(!evidenceRegistry[evidenceHash].exists, "Evidence already anchored");

        evidenceRegistry[evidenceHash] = EvidenceRecord({
            evidenceHash: evidenceHash,
            rawArtifactHash: rawArtifactHash,
            merkleRoot: merkleRoot,
            caseId: caseId,
            incidentType: incidentType,
            targetAsset: targetAsset,
            investigatorName: investigatorName,
            officerAddress: msg.sender,
            timestamp: block.timestamp,
            blockNumber: block.number,
            metadataUri: metadataUri,
            status: RecordStatus.ACTIVE,
            supersededBy: bytes32(0),
            exists: true
        });

        caseEvidenceMap[caseId].push(evidenceHash);
        totalEvidenceCount++;

        emit EvidenceStored(
            evidenceHash,
            rawArtifactHash,
            caseId,
            incidentType,
            msg.sender,
            block.timestamp,
            block.number
        );

        return true;
    }

    /**
     * @notice Supersede an existing evidence record with an amended forensic report.
     *         Never deletes records; preserves immutable chronological history.
     */
    function supersedeEvidence(
        bytes32 oldEvidenceHash,
        bytes32 newEvidenceHash,
        string calldata reason
    ) external onlyRole(ANALYST_ROLE) whenNotPaused returns (bool) {
        require(evidenceRegistry[oldEvidenceHash].exists, "Original evidence not found");
        require(evidenceRegistry[newEvidenceHash].exists, "New evidence must be anchored first");
        require(evidenceRegistry[oldEvidenceHash].status == RecordStatus.ACTIVE, "Record not active");

        evidenceRegistry[oldEvidenceHash].status = RecordStatus.SUPERSEDED;
        evidenceRegistry[oldEvidenceHash].supersededBy = newEvidenceHash;

        emit EvidenceSuperseded(
            oldEvidenceHash,
            newEvidenceHash,
            evidenceRegistry[oldEvidenceHash].caseId,
            msg.sender,
            reason
        );

        return true;
    }

    /**
     * @notice Verify whether a target evidence hash is anchored and unmodified.
     */
    function verifyEvidence(bytes32 evidenceHash) external returns (
        bool isAuthentic,
        bool isSuperseded,
        string memory caseId,
        uint256 timestamp,
        uint256 blockNumber,
        bytes32 rawArtifactHash
    ) {
        EvidenceRecord memory rec = evidenceRegistry[evidenceHash];
        if (!rec.exists || rec.status == RecordStatus.REVOKED) {
            emit EvidenceVerified(evidenceHash, false, "", block.timestamp);
            return (false, false, "", 0, 0, bytes32(0));
        }

        emit EvidenceVerified(evidenceHash, true, rec.caseId, block.timestamp);
        return (
            true,
            rec.status == RecordStatus.SUPERSEDED,
            rec.caseId,
            rec.timestamp,
            rec.blockNumber,
            rec.rawArtifactHash
        );
    }

    /**
     * @notice Verify a Merkle inclusion proof for a leaf in an anchored batch.
     *         Uses RFC 6962 domain separation (0x00 for leaf, 0x01 for internal node).
     */
    function verifyBatchInclusion(
        bytes32 leafHash,
        bytes32[] calldata proof,
        bool[] calldata isLeft,
        bytes32 batchEvidenceHash
    ) external view returns (bool) {
        EvidenceRecord memory rec = evidenceRegistry[batchEvidenceHash];
        if (!rec.exists || rec.merkleRoot == bytes32(0)) {
            return false;
        }

        require(proof.length == isLeft.length, "Proof and position length mismatch");

        bytes32 current = leafHash;
        for (uint256 i = 0; i < proof.length; i++) {
            if (isLeft[i]) {
                current = sha256(abi.encodePacked(uint8(0x01), proof[i], current));
            } else {
                current = sha256(abi.encodePacked(uint8(0x01), current, proof[i]));
            }
        }

        return current == rec.merkleRoot;
    }

    /**
     * @notice Retrieve details of an evidence record.
     */
    function getEvidenceRecord(bytes32 evidenceHash) external view returns (
        bytes32 rawArtifactHash,
        bytes32 merkleRoot,
        string memory caseId,
        string memory incidentType,
        string memory targetAsset,
        string memory investigatorName,
        address officerAddress,
        uint256 timestamp,
        uint256 blockNumber,
        RecordStatus status,
        bytes32 supersededBy
    ) {
        EvidenceRecord memory rec = evidenceRegistry[evidenceHash];
        require(rec.exists, "Record does not exist");
        return (
            rec.rawArtifactHash,
            rec.merkleRoot,
            rec.caseId,
            rec.incidentType,
            rec.targetAsset,
            rec.investigatorName,
            rec.officerAddress,
            rec.timestamp,
            rec.blockNumber,
            rec.status,
            rec.supersededBy
        );
    }

    /**
     * @notice Anchor the latest SQLite hash-chained ledger head onto the sovereign blockchain.
     * @param headHash SHA-256 digest of the current ledger head record.
     * @param recordCount Total number of records in the ledger (must be non-decreasing).
     */
    function anchorLedgerHead(
        bytes32 headHash,
        uint256 recordCount
    ) external onlyAuditorOrAdmin whenNotPaused returns (bool) {
        require(headHash != bytes32(0), "Invalid head hash");
        require(recordCount >= latestHead.recordCount, "Record count cannot decrease");

        latestHead = LedgerHead({
            headHash: headHash,
            recordCount: recordCount,
            timestamp: block.timestamp,
            blockNumber: block.number,
            submitter: msg.sender,
            exists: true
        });

        emit LedgerHeadAnchored(
            headHash,
            recordCount,
            msg.sender,
            block.timestamp,
            block.number
        );

        return true;
    }

    /**
     * @notice Retrieve the latest anchored ledger head state.
     */
    function getLatestHead() external view returns (
        bytes32 headHash,
        uint256 recordCount,
        uint256 timestamp,
        uint256 blockNumber,
        address submitter
    ) {
        return (
            latestHead.headHash,
            latestHead.recordCount,
            latestHead.timestamp,
            latestHead.blockNumber,
            latestHead.submitter
        );
    }
}
