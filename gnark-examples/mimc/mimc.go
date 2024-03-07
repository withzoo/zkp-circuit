package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	mimc, _ := mimc.NewMiMC(api)

	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())

	return nil
}

// hash函数
func hashCalc(preImage string) (string, string) {
	hi, _ := big.NewInt(0).SetString(preImage, 10)

	h := hash.MIMC_BN254.New()
	h.Write(hi.Bytes())
	rd := h.Sum(nil)
	r1 := big.NewInt(0).SetBytes(rd)

	return r1.String(), hex.EncodeToString(r1.Bytes())
}

func hashCalc1(preImage string) string {
	h := hash.MIMC_BN254.New()
	h.Write([]byte(preImage))
	rd := h.Sum(nil)
	r1 := big.NewInt(0).SetBytes(rd).String()
	return r1
}

func main() {
	// 外部系统生成Hash零知识证明电路
	var circuit Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	// Write solidity smart contract into a file
	contract, err := os.Create("mimc.sol")
	err = vk.ExportSolidity(contract)
	if err != nil {
		panic(err)
	}

	//根据原文计算hash值
	preImage := "16130099170765464552823636852555369511329944820189892919423002775646948828469"
	//preImage := "1"
	hash, hexHash := hashCalc(preImage)
	fmt.Println("hash:", hash)
	// witness definition
	assignment := Circuit{
		PreImage: preImage,
		Hash:     hash,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	var proofBuffer bytes.Buffer
	proofBuffer.Reset()
	proof.WriteRawTo(&proofBuffer)
	proofBuffer.Bytes()

	var vkBuffer bytes.Buffer
	vkBuffer.Reset()
	vk.WriteRawTo(&vkBuffer)
	vkBuffer.Bytes()

	fmt.Printf("proof: %s\n", hex.EncodeToString(proofBuffer.Bytes()))
	fmt.Printf("verifykey: %s\n", hex.EncodeToString(vkBuffer.Bytes()))
	//将上述产生的proof和verifykey字符串输出到文本中，方便复制粘贴！
	fileName := "mimc.txt"
	dstFile, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer dstFile.Close()
	str := "原文:" + preImage + "\n" + "Hash:" + hash + "\nHexHash:" + hexHash + "\nproof:" + hex.EncodeToString(proofBuffer.Bytes()) + "\n" + "verifykey:" + hex.EncodeToString(vkBuffer.Bytes())
	dstFile.WriteString(str + "\n")

	// VerifyProof 函数放到智能合约执行
	r, err := VerifyProof(hash, vkBuffer.Bytes(), proofBuffer.Bytes())
	if err != nil {
		panic(err)
	}
	if r {
		fmt.Println("验证通过!")
	} else {
		fmt.Println("验证失败!")
	}

}

func VerifyProof(hash string, verifyKey []byte, publicWitness []byte) (bool, error) {
	assignment1 := Circuit{
		Hash: hash,
	}
	publicWitness1, err := frontend.NewWitness(&assignment1, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, err
	}

	proof := groth16.NewProof(ecc.BN254)
	proof.ReadFrom(bytes.NewBuffer(publicWitness))

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(bytes.NewBuffer(verifyKey))

	err = groth16.Verify(proof, vk, publicWitness1)
	if err != nil {
		return false, err
	}
	return true, nil
}
