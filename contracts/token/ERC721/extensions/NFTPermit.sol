// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/Multicall.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract NFTPermit is ERC712, Multicall {
    using Counters for Counters.Counter;

    mapping (address => Counters.Counter) private _nonces;

    bytes32 private immutable _PERMIT721_TYPEHASH = keccak256("Permit721(address registry,uint256 tokenid,address from, address to,uint256 nonce,uint256 deadline)");
    bytes32 private immutable _PERMIT1155_TYPEHASH = keccak256("Permit1155(address registry,uint256 tokenid,address from, address to,uint256 value,uint256 nonce,uint256 deadline,bytes data)");

    constructor(string memory name)
    EIP712(name, "1")
    {}

    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }
    
    function transfer721WithSign(
        IERC721 registry,
        uint256 tokenId,
        address to,
        uint256 deadline,
        bytes memory signature
    ) 
        external
    {
        require(block.timestamp <= deadline, "NFTPermit::transfer721WithSign: Expired deadline");

        address from = registry.ownerOf(tokenId);
        require(
            SignatureChecker.isValidSignatureNow(
                from,
                _hashTypedDataV4(keccak256(abi.encode(
                    _PERMIT721_TYPEHASH,
                    registry,
                    tokenId,
                    from,
                    to,
                    _useNonce(from),
                    deadline
                ))),
                signature
            ),
            "NFTPermit::transfer721WithSign: Invalid signature"
        );

        registry.safeTransferFrom(from, to, tokenId);
    }

    function transfer1155WithSign(
        IERC1155 registry,
        uint256 tokenId,
        address from,
        address to,
        uint256 value,
        uint256 deadline,
        bytes memory data,
        bytes memory signature
    ) 
        external
    {
        require(block.timestamp <= deadline, "NFTPermit::transfer1155WithSign: Expired deadline");

        require(
            SignatureChecker.isValidSignatureNow(
                from,
                _hashTypedDataV4(keccak256(abi.encode(
                    _PERMIT1155_TYPEHASH,
                    registry,
                    tokenId,
                    from,
                    to,
                    value,
                    _useNonce(from),
                    deadline,
                    keccak256(data)
                ))),
                signature
            ),
            "NFTPermit::transfer1155WithSign: Invalid signature"
        );

        registry.safeTransferFrom(from, to, tokenId, value, data);
    }

    function nonces(address owner) external view virtual override returns (uint256) {
        return _nonces[owner].current();
    }

    function _useNonce(address owner) internal virtual returns (uint256 current) {
        Counters.Counter storage nonce = _nonces[owner];
        current = nonce.current();
        nonce.increment();
    }
}
