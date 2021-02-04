import { ApolloServer } from 'apollo-server';
import resolvers from './graphql/resolvers';
import typeDefs from './graphql/typeDefs';
import context from "./graphql/context";

const server = new ApolloServer({
	typeDefs,
	resolvers,
	context
});

server.listen().then(({ url }) => {
	console.log(`server ready at ${url}`);
});
