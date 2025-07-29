/* eslint-disable @typescript-eslint/no-explicit-any */
const ErrorFetchFeedbacks = ({error}:{error: any}) => {
  return (
    <div className="text-center text-2xl mt-4 text-red-500">
      some error occured
      {error?.message}
    </div>
  );
};

export default ErrorFetchFeedbacks;
