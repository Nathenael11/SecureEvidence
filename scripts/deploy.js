const { ethers, network } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error("No deployer signer available for network: " + network.name);
  }

  console.log(`Deploying EvidenceTracker to ${network.name} with deployer: ${deployer.address}`);

  const Factory = await ethers.getContractFactory("EvidenceTracker");
  const contract = await Factory.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log(`EvidenceTracker deployed at: ${contractAddress}`);

  // Resolve service address if specified in environment
  const serviceAddress = process.env.SERVICE_ADDRESS || process.env.SUBMITTER_ADDRESS || deployer.address;
  if (serviceAddress && serviceAddress.toLowerCase() !== deployer.address.toLowerCase()) {
    console.log(`Granting ANALYST_ROLE and AUDITOR_ROLE to service address: ${serviceAddress}`);
    const ANALYST_ROLE = await contract.ANALYST_ROLE();
    const AUDITOR_ROLE = await contract.AUDITOR_ROLE();
    const tx1 = await contract.grantRole(ANALYST_ROLE, serviceAddress);
    await tx1.wait();
    const tx2 = await contract.grantRole(AUDITOR_ROLE, serviceAddress);
    await tx2.wait();
    console.log(`Roles successfully granted to ${serviceAddress}`);
  }

  // Write deployment info (address only, no keys)
  const net = await ethers.provider.getNetwork();
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentRecord = {
    network: network.name,
    chainId: Number(net.chainId),
    contractAddress: contractAddress,
    deployerAddress: deployer.address,
    deployedAt: new Date().toISOString()
  };

  const outPath = path.join(deploymentsDir, `${network.name}.json`);
  fs.writeFileSync(outPath, JSON.stringify(deploymentRecord, null, 2), "utf-8");
  console.log(`Deployment metadata written to ${outPath}`);
}

main().catch((err) => {
  console.error("Deployment failed:", err);
  process.exitCode = 1;
});
