const ecc = require('eosjs-ecc')
const MerkleTree = require('merkletreejs')

const buf2hex = x => x.toString('hex')

const sha256 = x => Buffer.from(ecc.sha256(x), 'hex')
const leaves = ['a', 'b', 'c', 'd'].map(x => sha256(x))
const tree = new MerkleTree(leaves, sha256)
const root = buf2hex(tree.getRoot())
const leaf = buf2hex(tree.getLeaves()[0])
const proof = tree.getProof(leaves[0]).map(x => buf2hex(x.data))

console.log("root:", root)
console.log("leaf:", leaf)
console.log("proof:", proof)
