use alloy::sol;
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/05f218fb6617932e56bf5388c3b389c3028a7b73/contracts/utils/introspection/IERC165.sol
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IERC165 {
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
    }
);

// https://github.com/ensdomains/ens-contracts/blob/3c960892bf13e8317544b9287214dfc9af85f559/contracts/resolvers/profiles/IAddrResolver.sol
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IAddrResolver {
        event AddrChanged(bytes32 indexed node, address a);
        function addr(bytes32 node) external view returns (address payable);
    }
}

// https://github.com/ensdomains/ens-contracts/blob/3c960892bf13e8317544b9287214dfc9af85f559/contracts/resolvers/profiles/ITextResolver.sol
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ITextResolver {
        event TextChanged(
            bytes32 indexed node,
            string indexed indexedKey,
            string key,
            string value
        );
        function text(
            bytes32 node,
            string calldata key
        ) external view returns (string memory);
    }
}

// https://github.com/ensdomains/ens-contracts/blob/3c960892bf13e8317544b9287214dfc9af85f559/contracts/resolvers/profiles/IExtendedResolver.sol
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IExtendedResolver {
        function resolve(
            bytes memory name,
            bytes memory data
        ) external view returns (bytes memory);
    }
}

// https://eips.ethereum.org/EIPS/eip-3668#contract-interface
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IOffChain {
        error OffchainLookup(
            address sender,
            string[] urls,
            bytes callData,
            bytes4 callbackFunction,
            bytes extraData
        );
    }
}

//https://github.com/ensdomains/ens-contracts/blob/3c960892bf13e8317544b9287214dfc9af85f559/contracts/registry/ENS.sol
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ENS {
        event NewOwner(bytes32 indexed node, bytes32 indexed label, address owner);

        event Transfer(bytes32 indexed node, address owner);

        event NewResolver(bytes32 indexed node, address resolver);

        event NewTTL(bytes32 indexed node, uint64 ttl);

        event ApprovalForAll(
            address indexed owner,
            address indexed operator,
            bool approved
        );

        function setRecord(
            bytes32 node,
            address owner,
            address resolver,
            uint64 ttl
        ) external;

        function setSubnodeRecord(
            bytes32 node,
            bytes32 label,
            address owner,
            address resolver,
            uint64 ttl
        ) external;

        function setSubnodeOwner(
            bytes32 node,
            bytes32 label,
            address owner
        ) external returns (bytes32);

        function setResolver(bytes32 node, address resolver) external;

        function setOwner(bytes32 node, address owner) external;

        function setTTL(bytes32 node, uint64 ttl) external;

        function setApprovalForAll(address operator, bool approved) external;

        function owner(bytes32 node) external view returns (address);

        function resolver(bytes32 node) external view returns (address);

        function ttl(bytes32 node) external view returns (uint64);

        function recordExists(bytes32 node) external view returns (bool);

        function isApprovedForAll(
            address owner,
            address operator
        ) external view returns (bool);
    }
}
