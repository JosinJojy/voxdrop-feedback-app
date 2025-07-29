import { Feedback } from "@/models/UserModel";
import { ApiResponse } from "@/types/ApiResponse";
import {
  InfiniteData,
  useInfiniteQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import axios from "axios";

export function useFeedbacks(
  filters: { categoryId: string; type: string },
  isFiltersReady: boolean
) {
  return useInfiniteQuery({
    queryKey: ["feedbacks", filters],
    queryFn: async ({ pageParam }) => {
      const response = await axios.get<ApiResponse>(
        `/api/get-feedbacks?${pageParam ? `page=${pageParam}&categoryId=${filters.categoryId}&type=${filters.type}` : ``}`
      );
      return response.data;
    },
    initialPageParam: 1,
    getNextPageParam: (lastPage) => lastPage.nextPage,
    staleTime: 1000 * 60 * 1,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    refetchOnReconnect: false,
    enabled: isFiltersReady,
  });
}

export function useDeleteFeedback(filters: {
  categoryId: string;
  type: string;
}) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (DeleteFeedback: { id: string; categoryId: string }) => {
      const response = await axios.delete<ApiResponse>(`/api/delete-feedback`, {
        params: {
          feedbackId: DeleteFeedback?.id,
          categoryId: DeleteFeedback?.categoryId,
        },
      });
      return response.data;
    },
    onSuccess: async (_, DeleteFeedback) => {
      await queryClient.cancelQueries({ queryKey: ["feedbacks", filters] });

      type InifiniteFeedback =
        | InfiniteData<ApiResponse, number | undefined>
        | undefined;

      queryClient.setQueryData<InifiniteFeedback>(
        ["feedbacks", filters],
        (oldData) => {
          if (!oldData) return undefined;
          return {
            ...oldData,
            pages: oldData?.pages.map((page: ApiResponse) => ({
              ...page,
              feedbacks: page.feedbacks?.filter(
                (feedback: Feedback) => feedback._id !== DeleteFeedback?.id
              ),
            })),
            pageParams: oldData?.pageParams,
          };
        }
      );
    },
  });
}
