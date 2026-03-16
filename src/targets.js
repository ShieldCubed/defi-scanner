const axios = require("axios");
const { ethers } = require("ethers");

const ALCHEMY_KEY = process.env.ALCHEMY_KEY;
const RPC = `https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`;
const TVL_THRESHOLD = 1_000_000;

async function getHighTVLContracts() {
  console.log("Fetching protocols from DeFiLlama...");
  const { data } = await axios.get("https://api.llama.fi/protocols");
  const targets = data
    .filter(p => p.tvl >= TVL_THRESHOLD && p.chains?.includes("Ethereum"))
    .sort((a, b) => b.tvl - a.tvl)
    .slice(0, 20)
    .map(p => ({
      name: p.name,
      tvl: p.tvl,
      category: p.category,
      slug: p.slug,
    }));
  console.log(`Found ${targets.length} protocols above $${(TVL_THRESHOLD/1e6).toFixed(0)}M TVL`);
  return targets;
}

async function getProtocolContracts(slug) {
  try {
    const { data } = await axios.get(`https://api.llama.fi/protocol/${slug}`);
    const addresses = [];
    if (data.address && ethers.isAddress(data.address)) {
      addresses.push(data.address);
    }
    if (data.contracts?.ethereum) {
      for (const addr of Object.keys(data.contracts.ethereum)) {
        if (ethers.isAddress(addr)) addresses.push(addr);
      }
    }
    return [...new Set(addresses)];
  } catch (e) {
    return [];
  }
}

async function getContractDetails(address) {
  const provider = new ethers.JsonRpcProvider(RPC);
  const [bytecode, balance] = await Promise.all([
    provider.getCode(address),
    provider.getBalance(address),
  ]);
  return {
    address,
    bytecode,
    ethBalance: ethers.formatEther(balance),
    isContract: bytecode !== "0x",
  };
}

async function resolveContractAddresses(protocols) {
  const resolved = [];
  for (const p of protocols) {
    try {
      const addresses = await getProtocolContracts(p.slug);
      for (const addr of addresses.slice(0, 3)) {
        const details = await getContractDetails(addr);
        if (details.isContract && details.bytecode.length > 100) {
          resolved.push({ ...p, ...details });
          break;
        }
      }
    } catch (e) {}
  }
  console.log(`Resolved ${resolved.length} contract addresses\n`);
  return resolved;
}

module.exports = { getHighTVLContracts, getContractDetails, resolveContractAddresses };
