package main

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type merkleCircuit struct {
	MerkleProof   merkle.MerkleProof
	Nullifier     frontend.Variable
	Secret        frontend.Variable
	NullifierHash frontend.Variable `gnark:",public"`
}

func (circuit *merkleCircuit) Define(api frontend.API) error {
	nHash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	nHash.Write(circuit.Nullifier, circuit.Secret)
	api.AssertIsEqual(circuit.NullifierHash, nHash.Sum())

	commitment, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	commitment.Write(circuit.Nullifier, circuit.Secret)

	var treeLeaf frontend.Variable
	treeLeaf = commitment.Sum()

	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	circuit.MerkleProof.VerifyProof(api, &hFunc, treeLeaf)
	return nil
}

func main() {
	proofIndex := uint64(5)
	segmentSize := 32

	mod := ecc.BN254.ScalarField()
	modNbBytes := len(mod.Bytes())
	var buf bytes.Buffer
	for i := 0; i < segmentSize; i++ {
		leaf, err := crand.Int(crand.Reader, mod)
		if err != nil {
			return
		}
		b := leaf.Bytes()
		buf.Write(make([]byte, modNbBytes-len(b)))
		buf.Write(b)
	}

	hGo := hash.MIMC_BN254.New()
	merkleRoot, merkleProof, numLeaves, err := merkletree.BuildReaderProof(&buf, hGo, segmentSize, proofIndex)
	if err != nil {
		return
	}
	fmt.Printf("merkleRoot: %X\n", merkleRoot)
	fmt.Printf("numLeaves: %d\n", numLeaves)
	fmt.Printf("proof: %d\n", len(merkleProof))

	verified := merkletree.VerifyProof(hGo, merkleRoot, merkleProof, proofIndex, numLeaves)
	if !verified {
		fmt.Printf("The merkle proof in plain go should pass")
	}

	// create cs
	circuit := merkleCircuit{
		MerkleProof: merkle.MerkleProof{
			Path: make([]frontend.Variable, len(merkleProof)),
		},
	}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}

	// Write solidity smart contract into a file
	contract, err := os.Create("asset-mixer.sol")
	err = vk.ExportSolidity(contract)
	if err != nil {
		panic(err)
	}

	// witness
	var witness merkleCircuit
	witness.Leaf = proofIndex
	witness.MerkleProof.RootHash = merkleRoot
	witness.MerkleProof.Path = make([]frontend.Variable, len(merkleProof))
	for i := 0; i < len(merkleProof); i++ {
		witness.MerkleProof.Path[i] = merkleProof[i]
	}

	witnessProve, _ := frontend.NewWitness(&witness, ecc.BN254.ScalarField())

	proof, err := groth16.Prove(r1cs, pk, witnessProve)
	if err != nil {
		fmt.Printf("Prove failed： %v\n", err)
		return
	}

	witnessPublic, err := witnessProve.Public()
	err = groth16.Verify(proof, vk, witnessPublic)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")

}
